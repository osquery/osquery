/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.  
 * Copyright (C) 2004-2007 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _LVM_CONFIG_H
#define _LVM_CONFIG_H

#include "libdevmapper.h"

/* 16 bits: 3 bits for major, 4 bits for minor, 9 bits for patchlevel */
/* FIXME Max LVM version supported: 7.15.511. Extend bits when needed. */
#define vsn(major, minor, patchlevel) (major << 13 | minor << 9 | patchlevel)

struct device;
struct cmd_context;

typedef enum {
	CONFIG_UNDEFINED,	/* undefined/uninitialized config */
	CONFIG_FILE,		/* one file config */
	CONFIG_MERGED_FILES,	/* config that is a result of merging more config files */
	CONFIG_STRING,		/* config string typed on cmdline using '--config' arg */
	CONFIG_PROFILE_COMMAND,	/* command profile config */
	CONFIG_PROFILE_METADATA,/* metadata profile config */
	CONFIG_FILE_SPECIAL	/* special purpose file config (e.g. metadata, persistent filter...) */
} config_source_t;

struct profile {
	struct dm_list list;
	config_source_t source; /* either CONFIG_PROFILE_COMMAND or CONFIG_PROFILE_METADATA */
	const char *name;
	struct dm_config_tree *cft;
};

struct profile_params {
	char dir[PATH_MAX];                      /* subdir in LVM_SYSTEM_DIR where LVM looks for profiles */
	struct profile *global_command_profile;  /* profile (as given by --commandprofile cmd arg) used as global command profile */
	struct profile *global_metadata_profile; /* profile (as given by --metadataprofile cmd arg) that overrides any other VG/LV-based profile */
	struct dm_list profiles_to_load;         /* list of profiles which are only added, but still need to be loaded for any use */
	struct dm_list profiles;                 /* list of profiles which are loaded already and which are ready for use */
	struct profile *shell_profile;           /* master profile used in interactive/shell mode */
};

#define CFG_PATH_MAX_LEN 128

/*
 * Structures used for definition of a configuration tree.
 */

/* configuration definition item type (for item's accepted types) */
typedef enum {
	CFG_TYPE_SECTION =	1 << 0,	/* section */
	CFG_TYPE_ARRAY =	1 << 1,	/* setting */
	CFG_TYPE_BOOL =		1 << 2,	/* setting */
	CFG_TYPE_INT =		1 << 3,	/* setting */
	CFG_TYPE_FLOAT =	1 << 4,	/* setting */
	CFG_TYPE_STRING =	1 << 5,	/* setting */
} cfg_def_type_t;

/* function types to evaluate default value at runtime */
typedef int (*t_fn_CFG_TYPE_BOOL) (struct cmd_context *cmd, struct profile *profile);
typedef int (*t_fn_CFG_TYPE_INT) (struct cmd_context *cmd, struct profile *profile);
typedef float (*t_fn_CFG_TYPE_FLOAT) (struct cmd_context *cmd, struct profile *profile);
typedef const char* (*t_fn_CFG_TYPE_STRING) (struct cmd_context *cmd, struct profile *profile);
typedef const char* (*t_fn_CFG_TYPE_ARRAY) (struct cmd_context *cmd, struct profile *profile);
typedef const char* (*t_fn_UNCONFIGURED) (struct cmd_context *cmd);

/* configuration definition item value (for item's default value) */
typedef union {
	/* static value - returns a variable */
	const int v_CFG_TYPE_BOOL, v_CFG_TYPE_INT;
	const float v_CFG_TYPE_FLOAT;
	const char *v_CFG_TYPE_STRING, *v_CFG_TYPE_ARRAY;

	/* run-time value - evaluates a function */
	t_fn_CFG_TYPE_BOOL fn_CFG_TYPE_BOOL;
	t_fn_CFG_TYPE_INT fn_CFG_TYPE_INT;
	t_fn_CFG_TYPE_FLOAT fn_CFG_TYPE_FLOAT;
	t_fn_CFG_TYPE_STRING fn_CFG_TYPE_STRING;
	t_fn_CFG_TYPE_ARRAY fn_CFG_TYPE_ARRAY;
} cfg_def_value_t;

typedef union {
	const char *v_UNCONFIGURED;
	t_fn_UNCONFIGURED fn_UNCONFIGURED;
} cfg_def_unconfigured_value_t;

/* configuration definition item flags: */


/* whether the configuration item name is variable */
#define CFG_NAME_VARIABLE        0x0001
/* whether empty value is allowed */
#define CFG_ALLOW_EMPTY          0x0002
/* whether the configuration item is for advanced use only */
#define CFG_ADVANCED             0x0004
/* whether the configuration item is not officially supported */
#define CFG_UNSUPPORTED          0x0008
/* whether the configuration item is customizable by a profile */
#define CFG_PROFILABLE           0x0010
/* whether the configuration item is customizable by a profile
 * and whether it can be attached to VG/LV metadata at the same time
 * The CFG_PROFILABLE_METADATA flag incorporates CFG_PROFILABLE flag!!! */
#define CFG_PROFILABLE_METADATA  0x0030
/* whether the default value is undefned */
#define CFG_DEFAULT_UNDEFINED    0x0040
/* whether the default value is commented out on output */
#define CFG_DEFAULT_COMMENTED    0x0080
/* whether the default value is calculated during run time */
#define CFG_DEFAULT_RUN_TIME     0x0100
/* whether the configuration setting is disabled (and hence defaults always used) */
#define CFG_DISABLED             0x0200
/* whether to print integers in octal form (prefixed by "0") */
#define CFG_FORMAT_INT_OCTAL     0x0400
/* whether to disable checks for the whole config section subtree */
#define CFG_SECTION_NO_CHECK     0x0800
/* whether to disallow a possibility to override configuration
 * setting for commands run interactively (e.g. in lvm shell) */
#define CFG_DISALLOW_INTERACTIVE 0x1000

/* configuration definition item structure */
typedef struct cfg_def_item {
	int id;								/* ID of this item */
	int parent;							/* ID of parent item */
	const char *name;						/* name of the item in configuration tree */
	int type;							/* configuration item type (bits of cfg_def_type_t) */
	cfg_def_value_t default_value;					/* default value (only for settings) */
	uint16_t flags;							/* configuration item definition flags */
	uint16_t since_version;						/* version this item appeared in */
	cfg_def_unconfigured_value_t default_unconfigured_value;	/* default value in terms of @FOO@, pre-configured (only for settings) */
	uint16_t deprecated_since_version;				/* version since this item is deprecated */
	const char *deprecation_comment;				/* comment about reasons for deprecation and settings that supersede this one */
	const char *comment;						/* comment */
} cfg_def_item_t;

/* configuration definition tree types */
typedef enum {
	CFG_DEF_TREE_CURRENT,		/* tree of nodes with values currently set in the config */
	CFG_DEF_TREE_MISSING,		/* tree of nodes missing in current config using default values */
	CFG_DEF_TREE_FULL,		/* CURRENT + MISSING, the tree actually used within execution */
	CFG_DEF_TREE_DEFAULT,		/* tree of all possible config nodes with default values */
	CFG_DEF_TREE_NEW,		/* tree of all new nodes that appeared in given version */
	CFG_DEF_TREE_NEW_SINCE,		/* tree of all new nodes that appeared since given version */
	CFG_DEF_TREE_PROFILABLE,	/* tree of all nodes that are customizable by profiles */
	CFG_DEF_TREE_PROFILABLE_CMD,	/* tree of all nodes that are customizable by command profiles (subset of PROFILABLE) */
	CFG_DEF_TREE_PROFILABLE_MDA,	/* tree of all nodes that are customizable by metadata profiles (subset of PROFILABLE) */
	CFG_DEF_TREE_DIFF,		/* tree of all nodes that differ from defaults */
	CFG_DEF_TREE_LIST,		/* list all nodes */
} cfg_def_tree_t;

/* configuration definition tree specification */
struct config_def_tree_spec {
	struct cmd_context *cmd;		/* command context (for run-time defaults */
	struct dm_config_tree *current_cft;	/* current config tree which is defined explicitly - defaults are not used */
	cfg_def_tree_t type;			/* tree type */
	uint16_t version;			/* tree at this LVM2 version */
	unsigned ignoreadvanced:1;		/* do not include advanced configs */
	unsigned ignoreunsupported:1;		/* do not include unsupported configs */
	unsigned ignoredeprecated:1;		/* do not include deprecated configs */
	unsigned ignorelocal:1;			/* do not include the local section */
	unsigned withsummary:1;			/* include first line of comments - a summary */
	unsigned withcomments:1;		/* include all comment lines */
	unsigned withversions:1;		/* include versions */
	unsigned withspaces:1;			/* add more spaces in output for better readability */
	unsigned unconfigured:1;		/* use unconfigured path strings */
	uint8_t *check_status;			/* status of last tree check (currently needed for CFG_DEF_TREE_MISSING only) */
};


/* flag to mark the item as used in a config tree instance during validation */
#define CFG_USED		0x01
/* flag to mark the item as valid in a config tree instance during validation */
#define CFG_VALID		0x02
/* flag to mark the item as having the value different from default one */
#define CFG_DIFF		0x04

/*
 * Register ID for each possible item in the configuration tree.
 */
enum {
#define cfg_section(id, name, parent, flags, since_version, deprecated_since_version, deprecation_comment, comment) id,
#define cfg(id, name, parent, flags, type, default_value, since_version, unconfigured_value, deprecated_since_version, deprecation_comment, comment) id,
#define cfg_runtime(id, name, parent, flags, type, since_version, deprecated_since_version, deprecation_comment, comment) id,
#define cfg_array(id, name, parent, flags, types, default_value, since_version, unconfigured_value, deprecated_since_version, deprecation_comment, comment) id,
#define cfg_array_runtime(id, name, parent, flags, types, since_version, deprecated_since_version, deprecation_comment, comment) id,
#include "config_settings.h"
#undef cfg_section
#undef cfg
#undef cfg_runtime
#undef cfg_array
#undef cfg_array_runtime
};

struct profile *add_profile(struct cmd_context *cmd, const char *profile_name, config_source_t source);
int load_profile(struct cmd_context *cmd, struct profile *profile);
int load_pending_profiles(struct cmd_context *cmd);

/* configuration check handle for each instance of the validation check */
struct cft_check_handle {
	struct cmd_context *cmd;	/* command context */
	struct dm_config_tree *cft;	/* the tree for which the check is done */
	config_source_t source;		/* configuration source */
	unsigned force_check:1;		/* force check even if disabled by config/checks setting */
	unsigned skip_if_checked:1;	/* skip the check if already done before - return last state */
	unsigned suppress_messages:1;	/* suppress messages during the check if config item is found invalid */
	unsigned check_diff:1;		/* check if the value used differs from default one */
	unsigned ignoreadvanced:1;	/* do not include advnced configs */
	unsigned ignoreunsupported:1;	/* do not include unsupported configs */
	uint16_t disallowed_flags;	/* set of disallowed flags */
	uint8_t status[CFG_COUNT];	/* flags for each configuration item - the result of the check */
};

int config_def_get_path(char *buf, size_t buf_size, int id);
/* Checks config using given handle - the handle may be reused. */
int config_def_check(struct cft_check_handle *handle);
/* Forces config check and automatically creates a new handle inside with defaults and discards the handle after the check. */
int config_force_check(struct cmd_context *cmd, config_source_t source, struct dm_config_tree *cft);

int override_config_tree_from_string(struct cmd_context *cmd, const char *config_settings);
int override_config_tree_from_profile(struct cmd_context *cmd, struct profile *profile);
struct dm_config_tree *get_config_tree_by_source(struct cmd_context *, config_source_t source);
struct dm_config_tree *remove_config_tree_by_source(struct cmd_context *cmd, config_source_t source);
struct cft_check_handle *get_config_tree_check_handle(struct cmd_context *cmd, struct dm_config_tree *cft);
config_source_t config_get_source_type(struct dm_config_tree *cft);

typedef uint32_t (*checksum_fn_t) (uint32_t initial, const uint8_t *buf, uint32_t size);

struct dm_config_tree *config_open(config_source_t source, const char *filename, int keep_open);
int config_file_read_fd(struct dm_config_tree *cft, struct device *dev,
			off_t offset, size_t size, off_t offset2, size_t size2,
			checksum_fn_t checksum_fn, uint32_t checksum,
			int skip_parse, int no_dup_node_check);
int config_file_read(struct dm_config_tree *cft);
struct dm_config_tree *config_file_open_and_read(const char *config_file, config_source_t source,
						 struct cmd_context *cmd);
int config_write(struct dm_config_tree *cft, struct config_def_tree_spec *tree_spec,
		 const char *file, int argc, char **argv);
struct dm_config_tree *config_def_create_tree(struct config_def_tree_spec *spec);
void config_destroy(struct dm_config_tree *cft);

struct timespec config_file_timestamp(struct dm_config_tree *cft);
int config_file_changed(struct dm_config_tree *cft);
int config_file_check(struct dm_config_tree *cft, const char **filename, struct stat *info);


typedef enum {
	CONFIG_MERGE_TYPE_RAW,	/* always replace old config values with new config values when merging */
	CONFIG_MERGE_TYPE_TAGS	/* apply some exceptions when merging tag configs:
				     - skip tags section
				     - do not replace, but merge values of these settings:
					activation/volume_list
					devices/filter
					devices/types
				 */
} config_merge_t;

int merge_config_tree(struct cmd_context *cmd, struct dm_config_tree *cft,
		      struct dm_config_tree *newdata, config_merge_t);

/*
 * The next two do not check config overrides and must only be used for the tags section.
 */
const struct dm_config_node *find_config_node(struct cmd_context *cmd, struct dm_config_tree *cft, int id);
int find_config_bool(struct cmd_context *cmd, struct dm_config_tree *cft, int id);

/*
 * These versions check an override tree, if present, first.
 */
const struct dm_config_node *find_config_tree_node(struct cmd_context *cmd, int id, struct profile *profile);
const char *find_config_tree_str(struct cmd_context *cmd, int id, struct profile *profile);
const char *find_config_tree_str_allow_empty(struct cmd_context *cmd, int id, struct profile *profile);
int find_config_tree_int(struct cmd_context *cmd, int id, struct profile *profile);
int64_t find_config_tree_int64(struct cmd_context *cmd, int id, struct profile *profile);
float find_config_tree_float(struct cmd_context *cmd, int id, struct profile *profile);
int find_config_tree_bool(struct cmd_context *cmd, int id, struct profile *profile);
const struct dm_config_node *find_config_tree_array(struct cmd_context *cmd, int id, struct profile *profile);

/*
 * Functions for configuration settings for which the default
 * value is evaluated at runtime based on command context.
 */
const char *get_default_devices_cache_dir_CFG(struct cmd_context *cmd, struct profile *profile);
const char *get_default_unconfigured_devices_cache_dir_CFG(struct cmd_context *cmd);
const char *get_default_devices_cache_CFG(struct cmd_context *cmd, struct profile *profile);
const char *get_default_unconfigured_devices_cache_CFG(struct cmd_context *cmd);
const char *get_default_backup_backup_dir_CFG(struct cmd_context *cmd, struct profile *profile);
const char *get_default_unconfigured_backup_backup_dir_CFG(struct cmd_context *cmd);
const char *get_default_backup_archive_dir_CFG(struct cmd_context *cmd, struct profile *profile);
const char *get_default_unconfigured_backup_archive_dir_CFG(struct cmd_context *cmd);
const char *get_default_config_profile_dir_CFG(struct cmd_context *cmd, struct profile *profile);
const char *get_default_unconfigured_config_profile_dir_CFG(struct cmd_context *cmd);
const char *get_default_activation_mirror_image_fault_policy_CFG(struct cmd_context *cmd, struct profile *profile);
#define get_default_unconfigured_activation_mirror_image_fault_policy_CFG NULL
int get_default_allocation_thin_pool_chunk_size_CFG(struct cmd_context *cmd, struct profile *profile);
#define get_default_unconfigured_allocation_thin_pool_chunk_size_CFG NULL
int get_default_allocation_cache_pool_chunk_size_CFG(struct cmd_context *cmd, struct profile *profile);
#define get_default_unconfigured_allocation_cache_pool_chunk_size_CFG NULL
const char *get_default_allocation_cache_policy_CFG(struct cmd_context *cmd, struct profile *profile);
#define get_default_unconfigured_allocation_cache_policy_CFG NULL
uint64_t get_default_allocation_cache_pool_max_chunks_CFG(struct cmd_context *cmd, struct profile *profile);

#endif
