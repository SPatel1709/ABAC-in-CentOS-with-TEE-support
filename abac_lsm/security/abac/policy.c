/*
	ABAC policy parsing methods
	Copyright (C) <2021>  Hariyala Omkara Naga Sai Varshith
*/

#include <linux/fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "avp.h"
#include "policy.h"

void destroy_policy(abac_policy *p)
{
	abac_rule *cursor;
	abac_rule *to_free = NULL;

	if (!p)
		return;

	destroy_policy_tree(p->tree);
	cursor = p->rules;
	while (cursor != NULL) {
		destroy_avp_list(cursor->user);
		destroy_avp_list(cursor->object);
		destroy_avp_list(cursor->env);
		to_free = cursor;
		cursor = cursor->next;
		if (to_free)
			kfree(to_free);
	}
	kfree(p);
}

/* Print ABAC access mode */
char *abac_op_str(enum abac_op mode)
{
	if (mode == ABAC_READ)
		return "ABAC_READ";
	if (mode == ABAC_MODIFY)
		return "ABAC_MODIFY";
	return "ABAC_IGNORE";
}

char *abac_effect_str(enum abac_effect effect)
{
	if (effect == ABAC_DENY)
		return "ABAC_DENY";
	return "ABAC_ALLOW";
}

/* convert file permission mask to ABAC access type*/
enum abac_op convert_to_abac_op(int mask)
{
	if (mask & (MAY_WRITE | MAY_APPEND))
		return ABAC_MODIFY;
	if (mask & (MAY_READ | MAY_OPEN | MAY_ACCESS))
		return ABAC_READ;
	return ABAC_IGNORE;
}

static bool parse_rule_op(const char *token, enum abac_op *op)
{
	if (strncmp("MODIFY", token, 6) == 0) {
		*op = ABAC_MODIFY;
		return true;
	}
	if (strncmp("READ", token, 4) == 0) {
		*op = ABAC_READ;
		return true;
	}
	return false;
}

static enum abac_effect parse_rule_effect(const char *token)
{
	if (token && strncmp("DENY", token, 4) == 0)
		return ABAC_DENY;
	return ABAC_ALLOW;
}

static abac_rule *parse_line(char *buffer, int start, int end)
{
	abac_rule *r = kcalloc(1, sizeof(abac_rule), GFP_KERNEL);
	int user_delim_index;
	int object_delim_index;
	int env_delim_index;
	int effect_delim_index;

	user_delim_index = findidx(buffer, '|', start, end);
	object_delim_index = findidx(buffer, '|', user_delim_index + 1, end);
	env_delim_index = findidx(buffer, '|', object_delim_index + 1, end);
	effect_delim_index = findidx(buffer, '|', env_delim_index + 1, end);

	r->user = parse_avp_section(buffer, start, user_delim_index);
	r->object = parse_avp_section(buffer, user_delim_index + 1,
					      object_delim_index);
	if (buffer[object_delim_index + 1] != '*')
		r->env = parse_avp_section(buffer, object_delim_index + 1,
					   env_delim_index);

	r->op = ABAC_IGNORE;
	if (effect_delim_index == -1) {
		parse_rule_op(buffer + env_delim_index + 1, &r->op);
		r->effect = ABAC_ALLOW;
	} else {
		parse_rule_op(buffer + env_delim_index + 1, &r->op);
		r->effect = parse_rule_effect(buffer + effect_delim_index + 1);
	}
	return r;
}

abac_policy *parse_policy(char *buffer, int length)
{
	int start = 0;
	int end = 0;
	int i;
	int id = 0;
	abac_policy *policy;
	abac_rule *cursor, *head;

	if (buffer == NULL || length < 1)
		return NULL;

	policy = kcalloc(1, sizeof(abac_policy), GFP_KERNEL);
	cursor = NULL;
	head = NULL;
	for (i = 0; i < length; i++) {
		if (buffer[i] != '\n')
			continue;
		end = i;
		id++;
		if (cursor) {
			cursor->next = parse_line(buffer, start, end);
			cursor->next->id = id;
			cursor = cursor->next;
		} else {
			head = parse_line(buffer, start, end);
			cursor = head;
			cursor->id = id;
		}
		start = i + 1;
	}
	policy->rules = head;
	policy->tree = build_policy_tree(head);
	policy->count = id;
	return policy;
}

void print_abac_policy(abac_policy *p)
{
	abac_rule *r_cursor;
	avp *avp_cursor;

	r_cursor = p->rules;
	printk("Policy contains %d rules", p->count);
	while (r_cursor != NULL) {
		printk("------------------------------------------------");
		printk("ID: %d", r_cursor->id);
		printk("User attributes: ");
		avp_cursor = r_cursor->user;
		while (avp_cursor != NULL) {
			printk("%s=%s, ", avp_cursor->name, avp_cursor->value);
			avp_cursor = avp_cursor->next;
		}
		printk("Object attributes: ");
		avp_cursor = r_cursor->object;
		while (avp_cursor != NULL) {
			printk("%s=%s, ", avp_cursor->name, avp_cursor->value);
			avp_cursor = avp_cursor->next;
		}
		printk("Environment attributes: ");
		avp_cursor = r_cursor->env;
		while (avp_cursor != NULL) {
			printk("%s=%s, ", avp_cursor->name, avp_cursor->value);
			avp_cursor = avp_cursor->next;
		}
		printk("%s %s\n", abac_effect_str(r_cursor->effect),
		       abac_op_str(r_cursor->op));
		r_cursor = r_cursor->next;
	}
	printk("------------------------------------------------");
}
