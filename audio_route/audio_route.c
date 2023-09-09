/*
 * Copyright (C) 2013 The Android Open Source Project
 * Inspired by TinyHW, written by Mark Brown at Wolfson Micro
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "audio_route"
#define LOG_NDEBUG 0

#include <errno.h>
#include <expat.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <log/log.h>

#include <tinyalsa/asoundlib.h>

#ifdef __ANDROID_VNDK_SEC__
#include "include/audio_route/audio_route.h"
#endif

#define BUF_SIZE 1024
#define MIXER_XML_PATH "/system/etc/mixer_paths.xml"
#define INITIAL_MIXER_PATH_SIZE 8

enum update_direction {
    DIRECTION_FORWARD,
    DIRECTION_REVERSE,
    DIRECTION_REVERSE_RESET
};

union ctl_values {
    int *enumerated;
    long *integer;
    void *ptr;
    unsigned char *bytes;
};

struct mixer_state {
    struct mixer_ctl *ctl;
    unsigned int num_values;
    union ctl_values old_value;
    union ctl_values new_value;
    union ctl_values reset_value;
    unsigned int active_count;
};

struct mixer_setting {
    unsigned int ctl_index;
    unsigned int num_values;
    unsigned int type;
    union ctl_values value;
};

struct mixer_value {
    unsigned int ctl_index;
    int index;
    long value;
    /*
     memory pointed by this is allocated in start_tag during parsing ctl of
     MIXER_CTL_TYPE_BYTE or MIXER_CTL_TYPE_INT, and is released after the
     parsed values are updated to either setting value within a path,
     or top level initial setting value
     */
    long *values;
};

struct mixer_path {
    char *name;
    unsigned int size;
    unsigned int length;
    struct mixer_setting *setting;
};

#ifdef __ANDROID_VNDK_SEC__
struct path_list {
    const struct mixer_path **paths;
    unsigned int size;
    unsigned int length;
};
#endif

struct audio_route {
    struct mixer *mixer;
    unsigned int num_mixer_ctls;
    struct mixer_state *mixer_state;

    unsigned int mixer_path_size;
    unsigned int num_mixer_paths;
    struct mixer_path *mixer_path;
#ifdef __ANDROID_VNDK_SEC__
    struct path_list mixer_path_index;
    struct path_list applied_path;
    struct path_list reset_path;
    bool update_by_path;
    int32_t missing;
#endif
};

struct config_parse_state {
    struct audio_route *ar;
    struct mixer_path *path;
    int level;
};

#ifdef __ANDROID_VNDK_SEC__
static bool mixer_path_index_ready(struct audio_route *ar)
{
    return (ar->mixer_path_index.length > 0);
}

static const struct mixer_path *mixer_path_index_find(struct audio_route *ar, const char *name)
{
    struct path_list *index = &ar->mixer_path_index;
    int s, e, m, compare;

    if (!mixer_path_index_ready(ar))
        return NULL;

    s = 0;
    e = index->length - 1;
    while (s <= e) {
        m = (s + e) / 2;
        compare = strcmp(index->paths[m]->name, name);
        if (compare == 0)
            return index->paths[m];
        else if (compare < 0)
            s = m + 1;
        else
            e = m - 1;
    }

    return NULL;
}

static int path_list_add(struct path_list *list, const struct mixer_path *path);
static void path_list_free(struct path_list *list);

static int mixer_path_index_add(struct audio_route *ar, const struct mixer_path *path)
{
    struct path_list *index = &ar->mixer_path_index;
    int i, ret;

    ret = path_list_add(index, path);
    if (ret < 0)
        return ret;

    for (i = index->length - 1; i > 0; --i) {
        const struct mixer_path *temp;

        if (strcmp(index->paths[i - 1]->name, index->paths[i]->name) <= 0)
            break;

        temp = index->paths[i - 1];
        index->paths[i - 1] = index->paths[i];
        index->paths[i] = temp;
    }

    return 0;
}

static int mixer_path_index_init(struct audio_route *ar)
{
    const struct mixer_path *path;
    int ret;

    ALOGV("%s", __func__);

    for (path = ar->mixer_path; path - ar->mixer_path < ar->num_mixer_paths; path++) {
        ret = mixer_path_index_add(ar, path);
        if (ret < 0)
            break;
    }

    return ret;
}

static void mixer_path_index_free(struct audio_route *ar)
{
    path_list_free(&ar->mixer_path_index);
}
#endif

/* path functions */

static bool is_supported_ctl_type(enum mixer_ctl_type type)
{
    switch (type) {
    case MIXER_CTL_TYPE_BOOL:
    case MIXER_CTL_TYPE_INT:
    case MIXER_CTL_TYPE_ENUM:
    case MIXER_CTL_TYPE_BYTE:
        return true;
    default:
        return false;
    }
}

/* as they match in alsa */
static size_t sizeof_ctl_type(enum mixer_ctl_type type) {
    switch (type) {
    case MIXER_CTL_TYPE_BOOL:
    case MIXER_CTL_TYPE_INT:
        return sizeof(long);
    case MIXER_CTL_TYPE_ENUM:
        return sizeof(int);
    case MIXER_CTL_TYPE_BYTE:
        return sizeof(unsigned char);
    case MIXER_CTL_TYPE_INT64:
    case MIXER_CTL_TYPE_IEC958:
    case MIXER_CTL_TYPE_UNKNOWN:
    default:
        LOG_ALWAYS_FATAL("Unsupported mixer ctl type: %d, check type before calling", (int)type);
        return 0;
    }
}

static inline struct mixer_ctl *index_to_ctl(struct audio_route *ar,
                                             unsigned int ctl_index)
{
    return ar->mixer_state[ctl_index].ctl;
}

#if 0
static void path_print(struct audio_route *ar, struct mixer_path *path)
{
    unsigned int i;
    unsigned int j;

    ALOGE("Path: %s, length: %d", path->name, path->length);
    for (i = 0; i < path->length; i++) {
        struct mixer_ctl *ctl = index_to_ctl(ar, path->setting[i].ctl_index);

        ALOGE("  id=%d: ctl=%s", i, mixer_ctl_get_name(ctl));
        if (mixer_ctl_get_type(ctl) == MIXER_CTL_TYPE_BYTE) {
            for (j = 0; j < path->setting[i].num_values; j++)
                ALOGE("    id=%d value=0x%02x", j, path->setting[i].value.bytes[j]);
        } else if (mixer_ctl_get_type(ctl) == MIXER_CTL_TYPE_ENUM) {
            for (j = 0; j < path->setting[i].num_values; j++)
                ALOGE("    id=%d value=%d", j, path->setting[i].value.enumerated[j]);
        } else {
            for (j = 0; j < path->setting[i].num_values; j++)
                ALOGE("    id=%d value=%ld", j, path->setting[i].value.integer[j]);
        }
    }
}
#endif

static void path_free(struct audio_route *ar)
{
    unsigned int i;

    for (i = 0; i < ar->num_mixer_paths; i++) {
        free(ar->mixer_path[i].name);
        if (ar->mixer_path[i].setting) {
            size_t j;
            for (j = 0; j < ar->mixer_path[i].length; j++) {
                free(ar->mixer_path[i].setting[j].value.ptr);
            }
            free(ar->mixer_path[i].setting);
            ar->mixer_path[i].size = 0;
            ar->mixer_path[i].length = 0;
            ar->mixer_path[i].setting = NULL;
        }
    }
    free(ar->mixer_path);
    ar->mixer_path = NULL;
    ar->mixer_path_size = 0;
    ar->num_mixer_paths = 0;
}

static struct mixer_path *path_get_by_name(struct audio_route *ar,
                                           const char *name)
{
    unsigned int i;

#ifdef __ANDROID_VNDK_SEC__
    do {
        struct mixer_path *path;

        path = (struct mixer_path *)mixer_path_index_find(ar, name);
        if (path)
            return path;
    } while (0);
#endif
    for (i = 0; i < ar->num_mixer_paths; i++)
        if (strcmp(ar->mixer_path[i].name, name) == 0)
            return &ar->mixer_path[i];

    return NULL;
}

static struct mixer_path *path_create(struct audio_route *ar, const char *name)
{
    struct mixer_path *new_mixer_path = NULL;

    if (path_get_by_name(ar, name)) {
        ALOGW("Path name '%s' already exists", name);
        return NULL;
    }

    /* check if we need to allocate more space for mixer paths */
    if (ar->mixer_path_size <= ar->num_mixer_paths) {
        if (ar->mixer_path_size == 0)
            ar->mixer_path_size = INITIAL_MIXER_PATH_SIZE;
        else
            ar->mixer_path_size *= 2;

        new_mixer_path = realloc(ar->mixer_path, ar->mixer_path_size *
                                 sizeof(struct mixer_path));
        if (new_mixer_path == NULL) {
            ALOGE("Unable to allocate more paths");
            return NULL;
        } else {
            ar->mixer_path = new_mixer_path;
        }
    }

    /* initialise the new mixer path */
    ar->mixer_path[ar->num_mixer_paths].name = strdup(name);
    ar->mixer_path[ar->num_mixer_paths].size = 0;
    ar->mixer_path[ar->num_mixer_paths].length = 0;
    ar->mixer_path[ar->num_mixer_paths].setting = NULL;

    /* return the mixer path just added, then increment number of them */
    return &ar->mixer_path[ar->num_mixer_paths++];
}

static int find_ctl_index_in_path(struct mixer_path *path,
                                  unsigned int ctl_index)
{
    unsigned int i;

    for (i = 0; i < path->length; i++)
        if (path->setting[i].ctl_index == ctl_index)
            return i;

    return -1;
}

static int alloc_path_setting(struct mixer_path *path)
{
    struct mixer_setting *new_path_setting;
    int path_index;

    /* check if we need to allocate more space for path settings */
    if (path->size <= path->length) {
        if (path->size == 0)
            path->size = INITIAL_MIXER_PATH_SIZE;
        else
            path->size *= 2;

        new_path_setting = realloc(path->setting,
                                   path->size * sizeof(struct mixer_setting));
        if (new_path_setting == NULL) {
            ALOGE("Unable to allocate more path settings");
            return -1;
        } else {
            path->setting = new_path_setting;
        }
    }

    path_index = path->length;
    path->length++;

    return path_index;
}

static int path_add_setting(struct audio_route *ar, struct mixer_path *path,
                            struct mixer_setting *setting)
{
    int path_index;

    if (find_ctl_index_in_path(path, setting->ctl_index) != -1) {
        struct mixer_ctl *ctl = index_to_ctl(ar, setting->ctl_index);

        ALOGW("Control '%s' already exists in path '%s' - Ignore one in the new sub path",
              mixer_ctl_get_name(ctl), path->name);
        return -2;
    }

    if (!is_supported_ctl_type(setting->type)) {
        ALOGE("unsupported type %d", (int)setting->type);
        return -1;
    }

    path_index = alloc_path_setting(path);
    if (path_index < 0)
        return -1;

    path->setting[path_index].ctl_index = setting->ctl_index;
    path->setting[path_index].type = setting->type;
    path->setting[path_index].num_values = setting->num_values;

    size_t value_sz = sizeof_ctl_type(setting->type);

    path->setting[path_index].value.ptr = calloc(setting->num_values, value_sz);
    /* copy all values */
    memcpy(path->setting[path_index].value.ptr, setting->value.ptr,
           setting->num_values * value_sz);

    return 0;
}

static int path_add_value(struct audio_route *ar, struct mixer_path *path,
                          struct mixer_value *mixer_value)
{
    unsigned int i;
    int path_index;
    unsigned int num_values;
    struct mixer_ctl *ctl;

    /* Check that mixer value index is within range */
    ctl = index_to_ctl(ar, mixer_value->ctl_index);
    num_values = mixer_ctl_get_num_values(ctl);
    if (mixer_value->index >= (int)num_values) {
        ALOGE("mixer index %d is out of range for '%s'", mixer_value->index,
              mixer_ctl_get_name(ctl));
        return -1;
    }

    path_index = find_ctl_index_in_path(path, mixer_value->ctl_index);
    if (path_index < 0) {
        /* New path */

        enum mixer_ctl_type type = mixer_ctl_get_type(ctl);
        if (!is_supported_ctl_type(type)) {
            ALOGE("unsupported type %d", (int)type);
            return -1;
        }
        path_index = alloc_path_setting(path);
        if (path_index < 0)
            return -1;

        /* initialise the new path setting */
        path->setting[path_index].ctl_index = mixer_value->ctl_index;
        path->setting[path_index].num_values = num_values;
        path->setting[path_index].type = type;

        size_t value_sz = sizeof_ctl_type(type);
        path->setting[path_index].value.ptr = calloc(num_values, value_sz);
        if (path->setting[path_index].type == MIXER_CTL_TYPE_BYTE)
            path->setting[path_index].value.bytes[0] = mixer_value->value;
        else if (path->setting[path_index].type == MIXER_CTL_TYPE_ENUM)
            path->setting[path_index].value.enumerated[0] = mixer_value->value;
        else
            path->setting[path_index].value.integer[0] = mixer_value->value;
    }

    if (mixer_value->index == -1) {
        /* set all values the same except for CTL_TYPE_BYTE and CTL_TYPE_INT */
        if (path->setting[path_index].type == MIXER_CTL_TYPE_BYTE) {
            for (i = 0; i < num_values; i++)
                path->setting[path_index].value.bytes[i] = mixer_value->values[i];
        } else if (path->setting[path_index].type == MIXER_CTL_TYPE_INT) {
            for (i = 0; i < num_values; i++)
                path->setting[path_index].value.integer[i] = mixer_value->values[i];
        } else if (path->setting[path_index].type == MIXER_CTL_TYPE_ENUM) {
            for (i = 0; i < num_values; i++)
                path->setting[path_index].value.enumerated[i] = mixer_value->value;
        } else {
            for (i = 0; i < num_values; i++)
                path->setting[path_index].value.integer[i] = mixer_value->value;
        }
    } else {
        /* set only one value */
        if (path->setting[path_index].type == MIXER_CTL_TYPE_BYTE)
            path->setting[path_index].value.bytes[mixer_value->index] = mixer_value->value;
        else if (path->setting[path_index].type == MIXER_CTL_TYPE_ENUM)
            path->setting[path_index].value.enumerated[mixer_value->index] = mixer_value->value;
        else
            path->setting[path_index].value.integer[mixer_value->index] = mixer_value->value;
    }

    return 0;
}

static int path_add_path(struct audio_route *ar, struct mixer_path *path,
                         struct mixer_path *sub_path)
{
    unsigned int i;

    for (i = 0; i < sub_path->length; i++) {
        int retVal = path_add_setting(ar, path, &sub_path->setting[i]);
        if (retVal < 0) {
            if (retVal == -2)
                continue;
            else
                return -1;
        }
    }
    return 0;
}

#ifdef __ANDROID_VNDK_SEC__
static bool path_list_contains(const struct path_list *list, const struct mixer_path *path)
{
    const struct mixer_path * const * cur;

    for (cur = list->paths; cur - list->paths < list->length; cur++) {
        if (*cur == path)
            return true;
    }

    return false;
}

static int path_list_add(struct path_list *list, const struct mixer_path *path)
{
    void *new_buffer;
    unsigned int new_size;

    if (path_list_contains(list, path))
        return 0;

    if (list->size <= list->length) {
        new_size = list->size ? (list->size * 2) : 8;
        new_buffer = realloc(list->paths, new_size * sizeof(list->paths[0]));
        if (new_buffer == NULL) {
            ALOGE("Unable to allocate more paths");
            return -1;
        }
        list->paths = new_buffer;
        list->size = new_size;
    }
    list->paths[list->length++] = path;
    return 0;
}

static void path_list_clear(struct path_list *list)
{
    list->length = 0;
}

static void path_list_free(struct path_list *list)
{
    free(list->paths);
}

static void save_path_apply(struct audio_route *ar, const struct mixer_path *path, const struct mixer_setting *setting)
{
    struct mixer_state *ms = &ar->mixer_state[setting->ctl_index];
    size_t value_sz = sizeof_ctl_type(mixer_ctl_get_type(ms->ctl));

    if (!ar->update_by_path)
        return;

    if (ms->active_count > 0 && memcmp(ms->old_value.ptr, setting->value.ptr, setting->num_values * value_sz))
        ALOGW("Multi-activated mixer control %s with path %s", mixer_ctl_get_name(ms->ctl), path->name);
    ms->active_count++;
    path_list_add(&ar->applied_path, path);
}

static void save_path_reset(struct audio_route *ar, const struct mixer_path *path, const struct mixer_setting *setting)
{
    struct mixer_state *ms = &ar->mixer_state[setting->ctl_index];

    if (!ar->update_by_path)
        return;

    if (ms->active_count > 0)
        ms->active_count--;
    else
        ALOGW("Deactivate inactive mixer control %s with path %s", mixer_ctl_get_name(ms->ctl), path->name);
    path_list_add(&ar->reset_path, path);
}

static void free_path_lists(struct audio_route *ar)
{
    path_list_free(&ar->applied_path);
    path_list_free(&ar->reset_path);
}

void audio_route_update_mixer_by_path(struct audio_route *ar, bool set)
{
    ar->update_by_path = set;
}
#endif

static int path_apply(struct audio_route *ar, struct mixer_path *path)
{
    unsigned int i;
    unsigned int ctl_index;
    struct mixer_ctl *ctl;
    enum mixer_ctl_type type;

    ALOGD("Apply path: %s", path->name != NULL ? path->name : "none");
    for (i = 0; i < path->length; i++) {
        ctl_index = path->setting[i].ctl_index;
        ctl = index_to_ctl(ar, ctl_index);
        type = mixer_ctl_get_type(ctl);
        if (!is_supported_ctl_type(type))
            continue;
        size_t value_sz = sizeof_ctl_type(type);
#ifdef __ANDROID_VNDK_SEC__
        save_path_apply(ar, path, &path->setting[i]);
#endif
        memcpy(ar->mixer_state[ctl_index].new_value.ptr, path->setting[i].value.ptr,
                   path->setting[i].num_values * value_sz);
    }

    return 0;
}

static int path_reset(struct audio_route *ar, struct mixer_path *path)
{
    unsigned int i;
    unsigned int ctl_index;
    struct mixer_ctl *ctl;
    enum mixer_ctl_type type;

    ALOGV("Reset path: %s", path->name != NULL ? path->name : "none");
    for (i = 0; i < path->length; i++) {
        ctl_index = path->setting[i].ctl_index;
        ctl = index_to_ctl(ar, ctl_index);
        type = mixer_ctl_get_type(ctl);
        if (!is_supported_ctl_type(type))
            continue;
        size_t value_sz = sizeof_ctl_type(type);
#ifdef __ANDROID_VNDK_SEC__
        save_path_reset(ar, path, &path->setting[i]);
#endif
        /* reset the value(s) */
        memcpy(ar->mixer_state[ctl_index].new_value.ptr,
               ar->mixer_state[ctl_index].reset_value.ptr,
               ar->mixer_state[ctl_index].num_values * value_sz);
    }

    return 0;
}

/* mixer helper function */
static int mixer_enum_string_to_value(struct mixer_ctl *ctl, const char *string)
{
    unsigned int i;
    unsigned int num_values = mixer_ctl_get_num_enums(ctl);

    if (string == NULL) {
        ALOGE("NULL enum value string passed to mixer_enum_string_to_value() for ctl %s",
              mixer_ctl_get_name(ctl));
        return 0;
    }

    /* Search the enum strings for a particular one */
    for (i = 0; i < num_values; i++) {
        if (strcmp(mixer_ctl_get_enum_string(ctl, i), string) == 0)
            break;
    }
    if (i == num_values) {
        ALOGW("unknown enum value string %s for ctl %s",
              string, mixer_ctl_get_name(ctl));
        return 0;
    }
    return i;
}

#ifdef __ANDROID_VNDK_SEC__
static void start_tag(void *data, const XML_Char *tag_name, const XML_Char **attr);
static void end_tag(void *data, const XML_Char *tag_name);

static int process_include_tag(const char *xml_path, struct audio_route *ar)
{
    struct config_parse_state state;
    XML_Parser parser = NULL;
    FILE *file = NULL;
    void *buf;
    int bytes_read;
    int ret = 0;

    file = fopen(xml_path, "r");
    if (!file) {
        ALOGE("Failed to open %s: %s", xml_path, strerror(errno));
        ret = -1;
        goto error;
    }

    parser = XML_ParserCreate(NULL);
    if (!parser) {
        ALOGE("Failed to create XML parser");
        ret = -1;
        goto error;
    }

    memset(&state, 0, sizeof(state));
    state.ar = ar;
    XML_SetUserData(parser, &state);
    XML_SetElementHandler(parser, start_tag, end_tag);
    do {
        buf = XML_GetBuffer(parser, BUF_SIZE);
        if (buf == NULL) {
            ALOGE("Error in xml get buffer (%s)", xml_path);
            ret = -1;
            break;
        }

        bytes_read = fread(buf, 1, BUF_SIZE, file);
        if (bytes_read < 0) {
            ALOGE("Error in read xml file (%s)", xml_path);
            ret = -1;
            break;
        }

        if (XML_ParseBuffer(parser, bytes_read, bytes_read == 0) == XML_STATUS_ERROR) {
            ALOGE("Error in mixer xml (%s)", xml_path);
            ret = -1;
            break;
        }
    } while (bytes_read > 0);

error:
    if (parser)
        XML_ParserFree(parser);
    if (file)
        fclose(file);
    return ret;
}
#endif

static void start_tag(void *data, const XML_Char *tag_name,
                      const XML_Char **attr)
{
    const XML_Char *attr_name = NULL;
    const XML_Char *attr_id = NULL;
    const XML_Char *attr_value = NULL;
    struct config_parse_state *state = data;
    struct audio_route *ar = state->ar;
    unsigned int i;
    unsigned int ctl_index;
    struct mixer_ctl *ctl;
    long value;
    unsigned int id;
    struct mixer_value mixer_value;
    enum mixer_ctl_type type;
    long* value_array = NULL;

    /* Get name, id and value attributes (these may be empty) */
    for (i = 0; attr[i]; i += 2) {
        if (strcmp(attr[i], "name") == 0)
            attr_name = attr[i + 1];
        else if (strcmp(attr[i], "id") == 0)
            attr_id = attr[i + 1];
        else if (strcmp(attr[i], "value") == 0)
            attr_value = attr[i + 1];
    }

    /* Look at tags */
    if (strcmp(tag_name, "path") == 0) {
        if (attr_name == NULL) {
            ALOGE("Unnamed path!");
        } else {
            if (state->level == 1) {
                /* top level path: create and stash the path */
                state->path = path_create(ar, (char *)attr_name);
                if (state->path == NULL)
                    ALOGW("path creation failed, please check if the path exists");
            } else {
                /* nested path */
                struct mixer_path *sub_path = path_get_by_name(ar, attr_name);
                if (!sub_path) {
                    ALOGW("unable to find sub path '%s'", attr_name);
                } else if (state->path != NULL) {
                    path_add_path(ar, state->path, sub_path);
                }
            }
        }
    } else if (strcmp(tag_name, "ctl") == 0) {
        /* Obtain the mixer ctl and value */
        ctl = mixer_get_ctl_by_name(ar->mixer, attr_name);
        if (ctl == NULL) {
            ALOGW("Control '%s' doesn't exist - skipping", attr_name);
#ifdef __ANDROID_VNDK_SEC__
            ar->missing++;
#endif
            goto done;
        }

        switch (mixer_ctl_get_type(ctl)) {
        case MIXER_CTL_TYPE_BOOL:
            if (attr_value == NULL) {
                ALOGE("No value specified for ctl %s", attr_name);
                goto done;
            }
            value = strtol((char *)attr_value, NULL, 0);
            break;
        case MIXER_CTL_TYPE_INT:
        case MIXER_CTL_TYPE_BYTE: {
                char *attr_sub_value, *test_r;

                if (attr_value == NULL) {
                    ALOGE("No value specified for ctl %s", attr_name);
                    goto done;
                }
                unsigned int num_values = mixer_ctl_get_num_values(ctl);
                value_array = calloc(num_values, sizeof(long));
                if (!value_array) {
                    ALOGE("failed to allocate mem for ctl %s", attr_name);
                    goto done;
                }
                for (i = 0; i < num_values; i++) {
                    attr_sub_value = strtok_r((char *)attr_value, " ", &test_r);
                    if (attr_sub_value == NULL) {
                        ALOGE("expect %d values but only %d specified for ctl %s",
                            num_values, i, attr_name);
                        goto done;
                    }
                    if (mixer_ctl_get_type(ctl) == MIXER_CTL_TYPE_INT)
                        value_array[i] = strtol((char *)attr_sub_value, NULL, 0);
                    else
                        value_array[i] =
                           (unsigned char) strtol((char *)attr_sub_value, NULL, 16);

                    if (attr_id)
                        break;

                    attr_value = NULL;
                }
            } break;
        case MIXER_CTL_TYPE_ENUM:
            if (attr_value == NULL) {
                ALOGE("No value specified for ctl %s", attr_name);
                goto done;
            }
            value = mixer_enum_string_to_value(ctl, (char *)attr_value);
            break;
        default:
            value = 0;
            break;
        }

        /* locate the mixer ctl in the list */
        for (ctl_index = 0; ctl_index < ar->num_mixer_ctls; ctl_index++) {
            if (ar->mixer_state[ctl_index].ctl == ctl)
                break;
        }

        if (state->level == 1) {
            /* top level ctl (initial setting) */

            type = mixer_ctl_get_type(ctl);
            if (is_supported_ctl_type(type)) {
                /* apply the new value */
                if (attr_id) {
                    /* set only one value */
                    id = atoi((char *)attr_id);
                    if (id < ar->mixer_state[ctl_index].num_values)
                        if (type == MIXER_CTL_TYPE_BYTE)
                            ar->mixer_state[ctl_index].new_value.bytes[id] = value_array[0];
                        else if (type == MIXER_CTL_TYPE_INT)
                            ar->mixer_state[ctl_index].new_value.integer[id] = value_array[0];
                        else if (type == MIXER_CTL_TYPE_ENUM)
                            ar->mixer_state[ctl_index].new_value.enumerated[id] = value;
                        else
                            ar->mixer_state[ctl_index].new_value.integer[id] = value;
                    else
                        ALOGW("value id out of range for mixer ctl '%s'",
                              mixer_ctl_get_name(ctl));
                } else {
                    /* set all values the same except for CTL_TYPE_BYTE and CTL_TYPE_INT */
                    for (i = 0; i < ar->mixer_state[ctl_index].num_values; i++)
                        if (type == MIXER_CTL_TYPE_BYTE)
                            ar->mixer_state[ctl_index].new_value.bytes[i] = value_array[i];
                        else if (type == MIXER_CTL_TYPE_INT)
                            ar->mixer_state[ctl_index].new_value.integer[i] = value_array[i];
                        else if (type == MIXER_CTL_TYPE_ENUM)
                            ar->mixer_state[ctl_index].new_value.enumerated[i] = value;
                        else
                            ar->mixer_state[ctl_index].new_value.integer[i] = value;
                }
            }
        } else {
            /* nested ctl (within a path) */
            mixer_value.ctl_index = ctl_index;
            if (mixer_ctl_get_type(ctl) == MIXER_CTL_TYPE_BYTE ||
                mixer_ctl_get_type(ctl) == MIXER_CTL_TYPE_INT) {
                mixer_value.values = value_array;
                mixer_value.value = value_array[0];
            } else {
                mixer_value.value = value;
            }
            if (attr_id)
                mixer_value.index = atoi((char *)attr_id);
            else
                mixer_value.index = -1;
            if (state->path != NULL)
                path_add_value(ar, state->path, &mixer_value);
        }
    }
#ifdef __ANDROID_VNDK_SEC__
    else if (strcmp(tag_name, "include") == 0) {
        process_include_tag(attr_name, ar);
    }
#endif

done:
    free(value_array);
    state->level++;
}

static void end_tag(void *data, const XML_Char *tag_name)
{
    struct config_parse_state *state = data;
    (void)tag_name;

    state->level--;
}

static int alloc_mixer_state(struct audio_route *ar)
{
    unsigned int i;
    unsigned int num_values;
    struct mixer_ctl *ctl;
    enum mixer_ctl_type type;

    ar->num_mixer_ctls = mixer_get_num_ctls(ar->mixer);
    ALOGD("Num Mixer Controls = %d", ar->num_mixer_ctls);
    ar->mixer_state = calloc(ar->num_mixer_ctls, sizeof(struct mixer_state));
    if (!ar->mixer_state)
        return -1;

    for (i = 0; i < ar->num_mixer_ctls; i++) {
        ctl = mixer_get_ctl(ar->mixer, i);
        num_values = mixer_ctl_get_num_values(ctl);

        ar->mixer_state[i].ctl = ctl;
        ar->mixer_state[i].num_values = num_values;
        ar->mixer_state[i].active_count = 0;

        /* Skip unsupported types that are not supported yet in XML */
        type = mixer_ctl_get_type(ctl);

        if (!is_supported_ctl_type(type))
            continue;

        size_t value_sz = sizeof_ctl_type(type);
        ar->mixer_state[i].old_value.ptr = calloc(num_values, value_sz);
        ar->mixer_state[i].new_value.ptr = calloc(num_values, value_sz);
        ar->mixer_state[i].reset_value.ptr = calloc(num_values, value_sz);

        if (type == MIXER_CTL_TYPE_ENUM)
            ar->mixer_state[i].old_value.enumerated[0] = mixer_ctl_get_value(ctl, 0);
        else
            mixer_ctl_get_array(ctl, ar->mixer_state[i].old_value.ptr, num_values);

        memcpy(ar->mixer_state[i].new_value.ptr, ar->mixer_state[i].old_value.ptr,
               num_values * value_sz);
    }

    return 0;
}

static void free_mixer_state(struct audio_route *ar)
{
    unsigned int i;
    enum mixer_ctl_type type;

    for (i = 0; i < ar->num_mixer_ctls; i++) {
        type = mixer_ctl_get_type(ar->mixer_state[i].ctl);
        if (!is_supported_ctl_type(type))
            continue;

        free(ar->mixer_state[i].old_value.ptr);
        free(ar->mixer_state[i].new_value.ptr);
        free(ar->mixer_state[i].reset_value.ptr);
    }

    free(ar->mixer_state);
    ar->mixer_state = NULL;
}

/* Update the mixer with any changed values */
int audio_route_update_mixer(struct audio_route *ar)
{
    unsigned int i;
    unsigned int j;
    struct mixer_ctl *ctl;
    int ret = 0;

#ifdef __ANDROID_VNDK_SEC__
    if (ar->update_by_path)
        return audio_route_update_mixer_path(ar);
#endif

    for (i = 0; i < ar->num_mixer_ctls; i++) {
        unsigned int num_values = ar->mixer_state[i].num_values;
        enum mixer_ctl_type type;

        ctl = ar->mixer_state[i].ctl;

        /* Skip unsupported types */
        type = mixer_ctl_get_type(ctl);
        if (!is_supported_ctl_type(type))
            continue;

        /* if the value has changed, update the mixer */
        bool changed = false;
        if (type == MIXER_CTL_TYPE_BYTE) {
            for (j = 0; j < num_values; j++) {
                if (ar->mixer_state[i].old_value.bytes[j] != ar->mixer_state[i].new_value.bytes[j]) {
                    changed = true;
                    break;
                }
            }
         } else if (type == MIXER_CTL_TYPE_ENUM) {
             for (j = 0; j < num_values; j++) {
                 if (ar->mixer_state[i].old_value.enumerated[j]
                         != ar->mixer_state[i].new_value.enumerated[j]) {
                     changed = true;
                     break;
                 }
             }
         } else {
            for (j = 0; j < num_values; j++) {
                if (ar->mixer_state[i].old_value.integer[j] != ar->mixer_state[i].new_value.integer[j]) {
                    changed = true;
                    break;
                }
            }
        }
        if (changed) {
            if (type == MIXER_CTL_TYPE_ENUM) {
                ret = mixer_ctl_set_value(ctl, 0, ar->mixer_state[i].new_value.enumerated[0]);
                if (ret) {
                    ALOGE("ctl(%d)   : Fail to set (%d) : \"%s\" value \"%s\"", i, ret,
                        mixer_ctl_get_name(ctl),
                        mixer_ctl_get_enum_string(ctl, ar->mixer_state[i].new_value.enumerated[0]));
                } else {
                    ALOGV("ctl(%d)   : \"%s\" value \"%s\"", i, mixer_ctl_get_name(ctl),
                        mixer_ctl_get_enum_string(ctl, ar->mixer_state[i].new_value.enumerated[0]));
                }
            } else if (type == MIXER_CTL_TYPE_INT || type == MIXER_CTL_TYPE_BOOL) {
                ret = mixer_ctl_set_array(ctl, ar->mixer_state[i].new_value.integer, num_values);
                if (ret) {
                    ALOGE("ctl(%d)   : Fail to set (%d) : \"%s\" value %ld", i, ret,
                        mixer_ctl_get_name(ctl), ar->mixer_state[i].new_value.integer[0]);
                } else {
                    ALOGV("ctl(%d)   : \"%s\" value %ld", i, mixer_ctl_get_name(ctl),
                        ar->mixer_state[i].new_value.integer[0]);
                }
            } else {
                mixer_ctl_set_array(ctl, ar->mixer_state[i].new_value.ptr, num_values);
            }

            size_t value_sz = sizeof_ctl_type(type);
            memcpy(ar->mixer_state[i].old_value.ptr, ar->mixer_state[i].new_value.ptr,
                   num_values * value_sz);
        }
    }

    return 0;
}

/* saves the current state of the mixer, for resetting all controls */
static void save_mixer_state(struct audio_route *ar)
{
    unsigned int i;
    enum mixer_ctl_type type;

    for (i = 0; i < ar->num_mixer_ctls; i++) {
        type = mixer_ctl_get_type(ar->mixer_state[i].ctl);
        if (!is_supported_ctl_type(type))
            continue;

        size_t value_sz = sizeof_ctl_type(type);
        memcpy(ar->mixer_state[i].reset_value.ptr, ar->mixer_state[i].new_value.ptr,
               ar->mixer_state[i].num_values * value_sz);
    }
}

/* Reset the audio routes back to the initial state */
void audio_route_reset(struct audio_route *ar)
{
    unsigned int i;
    enum mixer_ctl_type type;

    ALOGI("> %s :", __FUNCTION__);

    /* load all of the saved values */
    for (i = 0; i < ar->num_mixer_ctls; i++) {
        type = mixer_ctl_get_type(ar->mixer_state[i].ctl);
        if (!is_supported_ctl_type(type))
            continue;

        size_t value_sz = sizeof_ctl_type(type);
        memcpy(ar->mixer_state[i].new_value.ptr, ar->mixer_state[i].reset_value.ptr,
            ar->mixer_state[i].num_values * value_sz);
    }
}

/* Apply an audio route path by name */
int audio_route_apply_path(struct audio_route *ar, const char *name)
{
    struct mixer_path *path;

    ALOGI("> %s : \"%s\"", __FUNCTION__, name);

    if (!ar) {
        ALOGE("invalid audio_route");
        return -1;
    }

    path = path_get_by_name(ar, name);
    if (!path) {
        ALOGE("unable to find path '%s'", name);
        return -1;
    }

    path_apply(ar, path);

    return 0;
}

/* Reset an audio route path by name */
int audio_route_reset_path(struct audio_route *ar, const char *name)
{
    struct mixer_path *path;

    if (!ar) {
        ALOGE("invalid audio_route");
        return -1;
    }

    path = path_get_by_name(ar, name);
    if (!path) {
        ALOGE("unable to find path '%s'", name);
        return -1;
    }

    path_reset(ar, path);

    return 0;
}

/*
 * Operates on the specified path .. controls will be updated in the
 * order listed in the XML file
 */
static int audio_route_update_path(struct audio_route *ar, const char *name, int direction)
{
    struct mixer_path *path;
    unsigned int j;
    int ret = 0;
    bool reverse = direction != DIRECTION_FORWARD;
    bool force_reset = direction == DIRECTION_REVERSE_RESET;

    ALOGI("> %s + : \"%s\" reverse(%d)", __FUNCTION__, name, reverse);

    if (!ar) {
        ALOGE("invalid audio_route");
        return -1;
    }

    path = path_get_by_name(ar, name);
    if (!path) {
        ALOGE("unable to find path '%s'", name);
        return -1;
    }

    ALOGI("> %s + : path length = %d", __FUNCTION__, path->length);
    for (size_t i = 0; i < path->length; ++i) {
        unsigned int ctl_index;
        enum mixer_ctl_type type;

        ctl_index = path->setting[reverse ? path->length - 1 - i : i].ctl_index;

        struct mixer_state * ms = &ar->mixer_state[ctl_index];

        type = mixer_ctl_get_type(ms->ctl);
        if (!is_supported_ctl_type(type)) {
            continue;
        }

        if (reverse && ms->active_count > 0) {
            if (force_reset)
                ms->active_count = 0;
            else
                ms->active_count--;
        } else if (!reverse) {
            ms->active_count++;
        }

       size_t value_sz = sizeof_ctl_type(type);
        /* if any value has changed, update the mixer */
        for (j = 0; j < ms->num_values; j++) {
            if (type == MIXER_CTL_TYPE_BYTE) {
                if (ms->old_value.bytes[j] != ms->new_value.bytes[j]) {
                    if (reverse && ms->active_count > 0) {
                        ALOGD("%s: skip to reset mixer control '%s' in path '%s' "
                            "because it is still needed by other paths", __func__,
                            mixer_ctl_get_name(ms->ctl), name);
                        memcpy(ms->new_value.bytes, ms->old_value.bytes,
                            ms->num_values * value_sz);
                        break;
                    }
                    mixer_ctl_set_array(ms->ctl, ms->new_value.bytes, ms->num_values);
                    memcpy(ms->old_value.bytes, ms->new_value.bytes, ms->num_values * value_sz);
                    break;
                }
            } else if (type == MIXER_CTL_TYPE_ENUM) {
                if (ms->old_value.enumerated[j] != ms->new_value.enumerated[j]) {
                    if (reverse && ms->active_count > 0) {
                        ALOGD("%s: skip to reset mixer control '%s' in path '%s' "
                            "because it is still needed by other paths", __func__,
                            mixer_ctl_get_name(ms->ctl), name);
                        memcpy(ms->new_value.enumerated, ms->old_value.enumerated,
                            ms->num_values * value_sz);
                        break;
                    }
                    ret = mixer_ctl_set_value(ms->ctl, 0, ms->new_value.enumerated[0]);
                    if (ret) {
                        ALOGE("ctl(%zu)   : Fail to set (%d) : \"%s\" value \"%s\"", i, ret,
                            mixer_ctl_get_name(ms->ctl),
                            mixer_ctl_get_enum_string(ms->ctl, ms->new_value.enumerated[0]));
                    } else {
                        ALOGV("ctl(%zu)   : \"%s\" value \"%s\"", i, mixer_ctl_get_name(ms->ctl),
                            mixer_ctl_get_enum_string(ms->ctl, ms->new_value.enumerated[0]));
                    }
                    memcpy(ms->old_value.enumerated, ms->new_value.enumerated,
                            ms->num_values * value_sz);
                    break;
                }
            } else if (ms->old_value.integer[j] != ms->new_value.integer[j]) {
                if (reverse && ms->active_count > 0) {
                    ALOGD("%s: skip to reset mixer control '%s' in path '%s' "
                        "because it is still needed by other paths", __func__,
                        mixer_ctl_get_name(ms->ctl), name);
                    memcpy(ms->new_value.integer, ms->old_value.integer,
                        ms->num_values * value_sz);
                    break;
                }
                ret = mixer_ctl_set_array(ms->ctl, ms->new_value.integer, ms->num_values);
                if (ret) {
                        ALOGE("ctl(%zu)   : Fail to set (%d) : \"%s\" value %ld", i, ret,
                            mixer_ctl_get_name(ms->ctl), ms->new_value.integer[0]);
                } else {
                        ALOGV("ctl(%zu)   : \"%s\" value %ld", i, mixer_ctl_get_name(ms->ctl),
                            ms->new_value.integer[0]);
                }
                memcpy(ms->old_value.integer, ms->new_value.integer, ms->num_values * value_sz);
                break;
            }
        }
    }
    return 0;
}

int audio_route_apply_and_update_path(struct audio_route *ar, const char *name)
{
    if (audio_route_apply_path(ar, name) < 0) {
        return -1;
    }
    return audio_route_update_path(ar, name, DIRECTION_FORWARD);
}

int audio_route_reset_and_update_path(struct audio_route *ar, const char *name)
{
    if (audio_route_reset_path(ar, name) < 0) {
        return -1;
    }
    return audio_route_update_path(ar, name, DIRECTION_REVERSE);
}

int audio_route_force_reset_and_update_path(struct audio_route *ar, const char *name)
{
    if (audio_route_reset_path(ar, name) < 0) {
        return -1;
    }

    return audio_route_update_path(ar, name, DIRECTION_REVERSE_RESET);
}

#ifdef __ANDROID_VNDK_SEC__
static int activate_path(struct audio_route *ar, const char *name)
{
    struct mixer_path *path;
    struct mixer_setting *setting;
    struct mixer_state *ms;

    path = path_get_by_name(ar, name);
    if (!path) {
        ALOGE("unable to find path '%s'", name);
        return -1;
    }

    ALOGD("Activate path: %s", path->name);
    for (setting = path->setting; setting - path->setting < path->length; setting++) {
        ms = &ar->mixer_state[setting->ctl_index];
        if (ms->active_count > 0 && memcmp(ms->new_value.ptr, setting->value.ptr, setting->num_values * sizeof_ctl_type(setting->type)))
            ALOGW("Multi-activated mixer control %s with path %s", mixer_ctl_get_name(ms->ctl), path->name);
        ms->active_count++;
        memcpy(ms->new_value.ptr, setting->value.ptr, setting->num_values * sizeof_ctl_type(setting->type));
    }

    return 0;
}

static int deactivate_path(struct audio_route *ar, const char *name)
{
    struct mixer_path *path;
    struct mixer_setting *setting;
    struct mixer_state *ms;

    path = path_get_by_name(ar, name);
    if (!path) {
        ALOGE("unable to find path '%s'", name);
        return -1;
    }

    ALOGV("Deactivate path: %s", path->name);
    for (setting = path->setting; setting - path->setting < path->length; setting++) {
        ms = &ar->mixer_state[setting->ctl_index];
        if (ms->active_count > 0)
            ms->active_count--;
        else
            ALOGW("Deactivate inactive mixer control %s with path %s", mixer_ctl_get_name(ms->ctl), path->name);
        memcpy(ms->new_value.ptr, ms->reset_value.ptr, ms->num_values * sizeof_ctl_type(setting->type));
    }

    return 0;
}

static bool mixer_state_is_changed(struct mixer_state *ms)
{
    size_t value_size = sizeof_ctl_type(mixer_ctl_get_type(ms->ctl));

    return !!memcmp(ms->old_value.ptr, ms->new_value.ptr, ms->num_values * value_size);
}


static char *mixer_state_sprint_value(const struct mixer_state *ms, const union ctl_values *value, char *buffer, size_t size)
{
    enum mixer_ctl_type type = mixer_ctl_get_type(ms->ctl);
    char *p = buffer;
    int res, i;

    switch (type) {
    case MIXER_CTL_TYPE_BYTE:
        res = snprintf(p, size, "%c", value->bytes[0]);
        break;
    case MIXER_CTL_TYPE_ENUM:
        res = snprintf(p, size, "%s", mixer_ctl_get_enum_string(ms->ctl, value->enumerated[0]));
        break;
    default:
        res = snprintf(p, size, "%ld", value->integer[0]);
        break;
    }
    if (res < 0)
        goto out;
    size -= res;
    p += res;

    for (i = 1; i < ms->num_values; i++) {
        if (size <= 2)
            break;

        switch (type) {
        case MIXER_CTL_TYPE_BYTE:
            res = snprintf(p, size, " %c", value->bytes[i]);
            break;
        case MIXER_CTL_TYPE_ENUM:
            res = snprintf(p, size, ", %s", mixer_ctl_get_enum_string(ms->ctl, value->enumerated[i]));
            break;
        default:
            res = snprintf(p, size, ", %ld", value->integer[i]);
            break;
        }
        if (res < 0)
            goto out;
        size -= res;
        p += res;
    }
out:
    *p = '\0';
    return buffer;
}

static char *mixer_state_sprint_new_value(const struct mixer_state *ms, char *buffer, size_t size)
{
    return mixer_state_sprint_value(ms, &ms->new_value, buffer, size);
}

static char *mixer_state_sprint_old_value(const struct mixer_state *ms, char *buffer, size_t size)
{
    return mixer_state_sprint_value(ms, &ms->old_value, buffer, size);
}

static int set_mixer_state_enum(struct mixer_state *ms)
{
    int ret = 0;

    for (int i = 0; i < ms->num_values; i++) {
        int res = mixer_ctl_set_value(ms->ctl, i, ms->new_value.enumerated[i]);
        if (res < 0)
            ret = res;
    }

    return ret;
}

static int set_mixer_state_integral(struct mixer_state *ms)
{
    return mixer_ctl_set_array(ms->ctl, ms->new_value.ptr, ms->num_values);
}

static int update_mixer_state(struct mixer_state *ms, bool reset)
{
    struct mixer_ctl *ctl = ms->ctl;
    const char *name = mixer_ctl_get_name(ctl);
    enum mixer_ctl_type type = mixer_ctl_get_type(ctl);
    size_t value_size = sizeof_ctl_type(type);
    int ret = 0;
    char buffer[128];

    if (!mixer_state_is_changed(ms)) {
        ALOGV("ctl : Skip to set : \"%s\" value \"%s\"", name, mixer_state_sprint_new_value(ms, buffer, sizeof(buffer)));
        return 0;
    }

    if (reset && ms->active_count > 0) {
        ALOGV("ctl : Skip to reset : \"%s\" value \"%s\"", name, mixer_state_sprint_old_value(ms, buffer, sizeof(buffer)));
        return 0;
    }

    switch (type) {
    case MIXER_CTL_TYPE_ENUM:
        ret = set_mixer_state_enum(ms);
        break;
    default:
        ret = set_mixer_state_integral(ms);
        break;
    }

    if (ret < 0)
        ALOGE("ctl : Fail to set (%d) : \"%s\" value \"%s\"", ret, name, mixer_state_sprint_new_value(ms, buffer, sizeof(buffer)));
    else
        ALOGD("ctl : \"%s\" value \"%s\"", name, mixer_state_sprint_new_value(ms, buffer, sizeof(buffer)));

    memcpy(ms->old_value.ptr, ms->new_value.ptr, ms->num_values * value_size);

    return ret;
}

static int update_reset_path(struct audio_route *ar, const struct mixer_path *path)
{
    const struct mixer_setting *setting;
    int res, ret = 0;

    for (setting = path->setting + path->length - 1; setting - path->setting >= 0; setting--) {
        res = update_mixer_state(&ar->mixer_state[setting->ctl_index], true);
        if (res < 0)
            ret = res;
    }

    return ret;
}

static int update_applied_path(struct audio_route *ar, const struct mixer_path *path)
{
    const struct mixer_setting *setting;
    int res, ret = 0;

    for (setting = path->setting; setting - path->setting < path->length; setting++) {
        res = update_mixer_state(&ar->mixer_state[setting->ctl_index], false);
        if (res < 0)
            ret = res;
    }

    return ret;
}

/*
 * Controls will be updated in the order listed in the XML file
 */
static int update_path(struct audio_route *ar, const char *name, bool reset)
{
    struct mixer_path *path;

    path = path_get_by_name(ar, name);
    if (!path) {
        ALOGE("unable to find path '%s'", name);
        return -1;
    }

    return reset ? update_reset_path(ar, path) : update_applied_path(ar, path);
}

int audio_route_exchange_and_update_path(struct audio_route *ar,
        const char **reset_path, unsigned int reset_paths,
        const char **apply_path, unsigned int apply_paths)
{
    const char **path_name;
    int ret = 0;

    if (!ar) {
        ALOGE("invalid audio_route");
        return -1;
    }

    /* reset path */
    for (path_name = reset_path + reset_paths - 1; path_name - reset_path >= 0; path_name--)
        deactivate_path(ar, *path_name);

    /* apply path */
    for (path_name = apply_path; path_name - apply_path < apply_paths; path_name++)
        activate_path(ar, *path_name);

    /* update reset path */
    for (path_name = reset_path + reset_paths - 1; path_name - reset_path >= 0; path_name--)
        update_path(ar, *path_name, true);

    /* update applied path */
    for (path_name = apply_path; path_name - apply_path < apply_paths; path_name++)
        update_path(ar, *path_name, false);

    return ret;
}

int audio_route_update_mixer_path(struct audio_route *ar)
{
    const struct mixer_path * const *path;

    if (!ar) {
        ALOGE("invalid audio_route");
        return -1;
    }

    if (!ar->update_by_path) {
        ALOGE("update mixer by path isn't enabled");
        return -1;
    }

    /* update reset path */
    for (path = ar->reset_path.paths + ar->reset_path.length - 1; path - ar->reset_path.paths >= 0; path--)
        update_reset_path(ar, *path);
    path_list_clear(&ar->reset_path);

    /* update applied path */
    for (path = ar->applied_path.paths; path - ar->applied_path.paths < ar->applied_path.length; path++)
        update_applied_path(ar, *path);
    path_list_clear(&ar->applied_path);

    return 0;
}

static int path_apply_value(struct audio_route *ar, const struct mixer_path *path, long value)
{
    unsigned int i, j;
    unsigned int ctl_index;
    struct mixer_ctl *ctl;
    enum mixer_ctl_type type;

    ALOGD("Apply path Value: %s Value: %ld", path->name != NULL ? path->name : "none", value);
    for (i = 0; i < path->length; i++) {
        ctl_index = path->setting[i].ctl_index;
        ctl = index_to_ctl(ar, ctl_index);
        type = mixer_ctl_get_type(ctl);
        if (!is_supported_ctl_type(type))
            continue;
        save_path_apply(ar, path, &path->setting[i]);
        for (j = 0; j < ar->mixer_state[ctl_index].num_values; j++) {
            if (type == MIXER_CTL_TYPE_BYTE)
                ar->mixer_state[ctl_index].new_value.bytes[j] = value;
            else if (type == MIXER_CTL_TYPE_INT)
                ar->mixer_state[ctl_index].new_value.integer[j] = value;
            else if (type == MIXER_CTL_TYPE_ENUM)
                ar->mixer_state[ctl_index].new_value.enumerated[j] = value;
            else
                ar->mixer_state[ctl_index].new_value.integer[j] = value;
        }
    }

    return 0;
}

/* Apply an audio route path (should contain only single control) by name & set the value */
int audio_route_apply_path_value(struct audio_route *ar, const char *name, long value)
{
    const struct mixer_path *path;

    ALOGI("> %s : \"%s\"", __FUNCTION__, name);

    if (!ar) {
        ALOGE("invalid audio_route");
        return -1;
    }

    path = path_get_by_name(ar, name);
    if (!path) {
        ALOGE("unable to find path '%s'", name);
        return -1;
    }

    path_apply_value(ar, path, value);

    return 0;
}

int audio_route_missing_ctl(struct audio_route *ar)
{
    if (!ar) {
        ALOGE("invalid audio_route");
        return 0;
    }

    return ar->missing;
}
#endif

struct audio_route *audio_route_init(unsigned int card, const char *xml_path)
{
    struct config_parse_state state;
    XML_Parser parser;
    FILE *file;
    int bytes_read;
    void *buf;
    struct audio_route *ar;

    ar = calloc(1, sizeof(struct audio_route));
    if (!ar)
        goto err_calloc;

    ar->mixer = mixer_open(card);
    if (!ar->mixer) {
        ALOGE("Unable to open the mixer, aborting.");
        goto err_mixer_open;
    }

    ar->mixer_path = NULL;
    ar->mixer_path_size = 0;
    ar->num_mixer_paths = 0;

    /* allocate space for and read current mixer settings */
    if (alloc_mixer_state(ar) < 0)
        goto err_mixer_state;

    /* use the default XML path if none is provided */
    if (xml_path == NULL)
        xml_path = MIXER_XML_PATH;

    file = fopen(xml_path, "r");

    if (!file) {
        ALOGE("Failed to open %s: %s", xml_path, strerror(errno));
        goto err_fopen;
    }

    parser = XML_ParserCreate(NULL);
    if (!parser) {
        ALOGE("Failed to create XML parser");
        goto err_parser_create;
    }

    memset(&state, 0, sizeof(state));
    state.ar = ar;
    XML_SetUserData(parser, &state);
    XML_SetElementHandler(parser, start_tag, end_tag);

    for (;;) {
        buf = XML_GetBuffer(parser, BUF_SIZE);
        if (buf == NULL)
            goto err_parse;

        bytes_read = fread(buf, 1, BUF_SIZE, file);
        if (bytes_read < 0)
            goto err_parse;

        if (XML_ParseBuffer(parser, bytes_read,
                            bytes_read == 0) == XML_STATUS_ERROR) {
            ALOGE("Error in mixer xml (%s)", MIXER_XML_PATH);
            goto err_parse;
        }

        if (bytes_read == 0)
            break;
    }

    /* apply the initial mixer values, and save them so we can reset the
       mixer to the original values */
    audio_route_update_mixer(ar);
    save_mixer_state(ar);
#ifdef __ANDROID_VNDK_SEC__
    mixer_path_index_init(ar);
#endif

    XML_ParserFree(parser);
    fclose(file);
    return ar;

err_parse:
    path_free(ar);
    XML_ParserFree(parser);
err_parser_create:
    fclose(file);
err_fopen:
    free_mixer_state(ar);
err_mixer_state:
    mixer_close(ar->mixer);
err_mixer_open:
    free(ar);
    ar = NULL;
err_calloc:
    return NULL;
}

void audio_route_free(struct audio_route *ar)
{
#ifdef __ANDROID_VNDK_SEC__
    mixer_path_index_free(ar);
    free_path_lists(ar);
#endif
    free_mixer_state(ar);
    mixer_close(ar->mixer);
    path_free(ar);
    free(ar);
}

#ifdef __ANDROID_VNDK_SEC__
/* Get pcm-dai information */
int get_dai_link(struct audio_route *ar, enum pcm_dai_link dai_link)
{
    if (ar)
        ALOGV("requested PCM for %d", dai_link);

    return -1;
}
#endif
