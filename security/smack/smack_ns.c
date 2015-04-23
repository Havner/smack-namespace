/*
 * Copyright (C) 2014 Samsung Electronics.
 *
 * Smack namespaces
 *
 * Author(s):
 *    Lukasz Pawelczyk <l.pawelczyk@samsung.com>
 *
 * This program is free software, you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/file.h>
#include <linux/ctype.h>
#include <linux/rculist.h>
#include <linux/seq_file.h>
#include <linux/user_namespace.h>
#include "smack.h"

/**
 * smk_find_mapped_ns - Finds a first namespace from this one through
 * its parrents that has a map. This map is the effective map in this
 * namespace.
 * @ns: a user namespace for which we search for a mapped ns
 *
 * Returns a namespace that has a non-NULL map, or NULL if there is
 * no mapped namespace.
 *
 * Can be effectively used to answer a question: "is there a Smack
 * map for this namespace?"
 */
struct user_namespace *smk_find_mapped_ns(struct user_namespace *ns)
{
	struct user_namespace *user_ns = ns;

	do {
		struct smack_ns *sns = user_ns->security;

		if (sns && !list_empty(&sns->smk_mapped))
			break;

		user_ns = user_ns->parent;
	} while (user_ns);

	return user_ns;
}

/**
 * __smk_find_mapped - an internal version of smk_find_mapped
 *                     that doesn't use smk_find_mapped_ns, but
 *                     operates directly on the passed one.
 */
static struct smack_known_ns *__smk_find_mapped(struct smack_known *skp,
						struct user_namespace *ns)
{
	struct smack_known_ns *sknp;

	if (ns == NULL)
		return NULL;

	list_for_each_entry_rcu(sknp, &skp->smk_mapped, smk_list_known)
		if (sknp->smk_ns == ns)
			return sknp;

	return NULL;
}

/**
 * smk_find_mapped - Finds a mapped label on the smack_known's mapped list
 * @skp: a label which mapped label we look for
 * @ns: a user namespace the label we search for is assigned to
 *
 * Returns a pointer to the mapped label if one exists that is
 * assigned to the specified user namespace or NULL if not found.
 */
struct smack_known_ns *smk_find_mapped(struct smack_known *skp,
				       struct user_namespace *ns)
{
	struct user_namespace *user_ns = smk_find_mapped_ns(ns);

	return __smk_find_mapped(skp, user_ns);
}

/**
 * __smk_find_unmapped - an internal version of smk_find_unmapped
 *                       that doesn't use smk_find_mapped_ns, but
 *                       operates directly on the passed one.
 */
static struct smack_known *__smk_find_unmapped(const char *string, int len,
					       struct user_namespace *ns)
{
	struct smack_ns *snsp;
	struct smack_known *skp = NULL;
	struct smack_known_ns *sknp;
	char *smack;
	bool allocated = false;

	if (ns == NULL)
		return NULL;

	snsp = ns->security;

	smack = smk_parse_smack(string, len, &allocated);
	if (IS_ERR(smack))
		return ERR_CAST(smack);

	list_for_each_entry_rcu(sknp, &snsp->smk_mapped, smk_list_ns) {
		if (strcmp(smack, sknp->smk_mapped) == 0) {
			skp = sknp->smk_unmapped;
			break;
		}
	}

	if (allocated)
		kfree(smack);
	return skp;
}

/**
 * smk_find_unmapped - Finds an original label by a mapped label string
 *                     and the namespace it could be mapped in
 * @string: a name of a mapped label we look for
 * @len: the string size, or zero if it is NULL terminated.
 * @ns: a namespace the looked for label should be mapped in
 *
 * Returns a smack_known label that is mapped as 'string' in 'ns',
 * NULL if not found or an error code.
 */
struct smack_known *smk_find_unmapped(const char *string, int len,
				      struct user_namespace *ns)
{
	struct user_namespace *user_ns = smk_find_mapped_ns(ns);

	return __smk_find_unmapped(string, len, user_ns);
}

/**
 * smk_import_mapped - Imports a mapped label effectively creating a mapping.
 * @skp: a label we map
 * @ns: a user namespace this label will be mapped in
 * @string: a text string of the mapped label
 * @len: the maximum size, or zero if it is NULL terminanted
 *
 * Returns a pointer to the mapped label entry or an error code.
 *
 * The mapped label will be added to 2 lists:
 *   - a list of mapped labels of skp
 *   - a list of labels mapped in ns
 */
static struct smack_known_ns *smk_import_mapped(struct smack_known *skp,
						struct user_namespace *ns,
						const char *string, int len)
{
	struct smack_ns *snsp = ns->security;
	struct smack_known_ns *sknp;
	char *mapped;
	bool allocated;

	/* Mapping init_user_ns is against the design and pointless */
	if (ns == &init_user_ns)
		return ERR_PTR(-EBADR);

	mapped = smk_parse_smack(string, len, &allocated);
	if (IS_ERR(mapped))
		return ERR_CAST(mapped);

	mutex_lock(&skp->smk_mapped_lock);

	/*
	 * Don't allow one<->many mappings in namespace, rename.
	 * This code won't get triggered for now as trying to assign
	 * a duplicate is forbidden in proc_smack_map_write().
	 * Leaving this as this function might be also used elsewhere.
	 */
	sknp = smk_find_mapped(skp, ns);
	if (sknp != NULL) {
		if (sknp->smk_allocated)
			kfree(sknp->smk_mapped);
		sknp->smk_mapped = mapped;
		sknp->smk_allocated = allocated;
		goto unlockout;
	}

	sknp = kzalloc(sizeof(*sknp), GFP_KERNEL);
	if (sknp == NULL) {
		sknp = ERR_PTR(-ENOMEM);
		if (allocated)
			kfree(mapped);
		goto unlockout;
	}

	sknp->smk_ns = ns;
	sknp->smk_mapped = mapped;
	sknp->smk_allocated = allocated;
	sknp->smk_unmapped = skp;
	list_add_rcu(&sknp->smk_list_known, &skp->smk_mapped);

	mutex_lock(&snsp->smk_mapped_lock);
	list_add_rcu(&sknp->smk_list_ns, &snsp->smk_mapped);
	mutex_unlock(&snsp->smk_mapped_lock);

unlockout:
	mutex_unlock(&skp->smk_mapped_lock);

	return sknp;
}

/**
 * smk_labels_valid - A helper to check whether labels are valid/mapped
 *                    in the namespace and can be used there
 * @sbj: a subject label to be checked
 * @obj: an object label to be checked
 * @ns: user namespace to check against (usually subject's)
 *
 * Returns true if both valid/mapped, false otherwise.
 * This helper is mostly used while checking capabilities.
 * The access functions check the validity of labels by themselves.
 */
bool smk_labels_valid(struct smack_known *sbj, struct smack_known *obj,
		      struct user_namespace *ns)
{
	struct user_namespace *user_ns;

	/*
	 * labels are always valid if there is no map
	 * (init_user_ns or unmapped descendants)
	 */
	user_ns = smk_find_mapped_ns(ns);
	if (user_ns == NULL)
		return true;

	/*
	 * If we have a map though, both labels need to be mapped.
	 */
	if (__smk_find_mapped(sbj, user_ns) == NULL)
		return false;
	if (__smk_find_mapped(obj, user_ns) == NULL)
		return false;

	return true;
}

/*
 * proc mapping operations
 */

static void *proc_smack_map_seq_start(struct seq_file *seq, loff_t *pos)
{
	struct smack_known *skp;
	struct user_namespace *ns = seq->private;
	loff_t counter = *pos;

	rcu_read_lock();
	list_for_each_entry_rcu(skp, &smack_known_list, list)
		if (smk_find_mapped(skp, ns) && counter-- == 0)
			return skp;

	return NULL;
}

static void proc_smack_map_seq_stop(struct seq_file *seq, void *v)
{
	rcu_read_unlock();
}

static void *proc_smack_map_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct smack_known *skp = v;
	struct user_namespace *ns = seq->private;

	list_for_each_entry_continue_rcu(skp, &smack_known_list, list) {
		if (smk_find_mapped(skp, ns)) {
			(*pos)++;
			return skp;
		}
	}

	return NULL;
}

static int proc_smack_map_seq_show(struct seq_file *seq, void *v)
{
	struct smack_known *skp = v;
	struct user_namespace *ns = seq->private;
	struct smack_known_ns *sknp;

	/*
	 * QUESTION: linux-api
	 * What to print when in init_map_ns where the map is empty
	 * effectively meaning identity? Unfortunately it's impossible
	 * to show identity in this syntax without printing all the labels.
	 */
	if (smk_find_mapped_ns(ns) == NULL) {
		seq_puts(seq, "This namespace is not mapped.\n");
	} else {
		sknp = smk_find_mapped(skp, ns);
		if (sknp)
			seq_printf(seq, "%s -> %s\n",
				   skp->smk_known, sknp->smk_mapped);
	}

	return 0;
}

const struct seq_operations proc_smack_map_seq_operations = {
	.start = proc_smack_map_seq_start,
	.stop = proc_smack_map_seq_stop,
	.next = proc_smack_map_seq_next,
	.show = proc_smack_map_seq_show,
};

static DEFINE_MUTEX(smk_map_mutex);

static bool mapping_permitted(const struct file *file,
			      struct user_namespace *user_ns)
{
	/*
	 * Do not allow mapping own label. This is in contrast to user
	 * namespace where you can always map your own UID. In Smack having
	 * administrative privileges over your own label (which Smack
	 * namespace effectively gives you) is not equivalent to user
	 * namespace. E.g. things like setting exec/transmute labels that
	 * otherwise would be denied. Hence no own_label param here.
	 */

	/*
	 * Adjusting namespace settings requires capabilities on the target.
	 */
	if (!file_ns_capable(file, user_ns, CAP_MAC_ADMIN))
		return false;

	/*
	 * And it requires capabilities in the parent.
	 *
	 * If the Smack namespace was properly hierarchical the user_ns to
	 * check against could be 'user_ns->parent'. Right now because of
	 * security concerns only privileged initial namespace is allowed
	 * to fill the map. For a hierarchical namespaces one would
	 * implement mapping (in the child namespaces) of only mapped labels
	 * (in parent namespace) and change '&init_user_ns' to
	 * 'user_ns->parent'. This will be added in the future.
	 */
	if (smack_ns_privileged(&init_user_ns, CAP_MAC_ADMIN) &&
	    file_ns_capable(file, &init_user_ns, CAP_MAC_ADMIN))
		return true;

	return false;
}

ssize_t proc_smack_map_write(struct file *file, const char __user *buf,
			     size_t size, loff_t *ppos)
{
	struct seq_file *seq = file->private_data;
	struct user_namespace *ns = seq->private;
	struct user_namespace *seq_ns = seq_user_ns(seq);
	struct smack_known *skp;
	struct smack_known_ns *sknp;
	unsigned long page = 0;
	char *kbuf, *pos, *next_line, *tok[2];
	ssize_t ret;
	int i;

	/* Mapping labels for the init ns makes no sense */
	if (ns == &init_user_ns)
		return -EBADR;

	if ((seq_ns != ns) && (seq_ns != ns->parent))
		return -EPERM;

	mutex_lock(&smk_map_mutex);

	ret = -EPERM;
	if (!mapping_permitted(file, ns))
		goto out;

	/* Get a buffer */
	ret = ENOMEM;
	page = __get_free_page(GFP_TEMPORARY);
	if (!page)
		goto out;
	kbuf = (char *)page;

	/* Only allow <= page size writes at the beginning of the file */
	ret = -EINVAL;
	if ((*ppos != 0) || (size >= PAGE_SIZE))
		goto out;

	/* Slurp in the user data */
	ret = -EFAULT;
	if (copy_from_user(kbuf, buf, size))
		goto out;
	kbuf[size] = '\0';

	/* Parse the user data */
	pos = kbuf;

	for (; pos; pos = next_line) {
		ret = -EINVAL;

		/* Find the end of line and ensure I don't look past it */
		next_line = strchr(pos, '\n');
		if (next_line) {
			*next_line = '\0';
			next_line++;
			if (*next_line == '\0')
				next_line = NULL;
		}

		/* Find tokens in line */
		for (i = 0; i < 2; ++i) {
			while (isspace(*pos))
				*(pos++) = '\0';

			/* unexpected end of file */
			if (*pos == '\0')
				goto out;

			tok[i] = pos;

			/* find the end of the token */
			while (*pos != '\0' && !isspace(*pos))
				++pos;
		}

		/* NUL terminate the last token if not EOL */
		while (isspace(*pos))
			*(pos++) = '\0';

		/* there should not be any trailing data */
		if (*pos != '\0')
			goto out;

		/* do not allow to map 2 different labels to one name */
		skp = __smk_find_unmapped(tok[1], 0, ns);
		if (IS_ERR(skp)) {
			ret = PTR_ERR(skp);
			goto out;
		}
		if (skp != NULL) {
			ret = -EEXIST;
			goto out;
		}

		skp = smk_import_entry(tok[0], 0);
		if (IS_ERR(skp)) {
			ret = PTR_ERR(skp);
			goto out;
		}

		/* do not allow remapping */
		ret = -EEXIST;
		if (__smk_find_mapped(skp, ns))
			goto out;

		sknp = smk_import_mapped(skp, ns, tok[1], 0);
		if (IS_ERR(sknp)) {
			ret = PTR_ERR(sknp);
			goto out;
		}
	}

	ret = size;

out:
	mutex_unlock(&smk_map_mutex);
	if (page)
		free_page(page);

	return ret;
}
