/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef AUDIO_ROUTE_H
#define AUDIO_ROUTE_H

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef __ANDROID_VNDK_SEC__
enum pcm_dai_link {
    PLAYBACK_LINK,
    PLAYBACK_LOW_LINK,
    PLAYBACK_DEEP_LINK,
    PLAYBACK_OFFLOAD_LINK,
    PLAYBACK_AUX_DIGITAL_LINK,
    PLAYBACK_DIRECT_LINK,
    PLAYBACK_DEEP_DIRECT_LINK, //calliope 3.0 Deep playback link for rate > 48Khz
    PLAYBACK_TELEPHONYTX_LINK, // incall-music playback link
    PLAYBACK_INCALL_MUSIC_LINK,
    CAPTURE_LINK,
    BASEBAND_LINK,
    BASEBAND_CAPTURE_LINK,
    BLUETOOTH_LINK,
    BLUETOOTH_CAPTURE_LINK,
    VTS_CAPTURE_LINK,
    VTS_SEAMLESS_CATURE_LINK,
    CALL_REC_CAPTURE_LINK,
    FMRADIO_LINK,
    CAPTURE_CALLMIC_LINK,
    TELEPHONYRX_CAPTURE_LINK,
    PLAYBACK_VOIP_LINK,
    NUM_DAI_LINK,
};
#endif

/* Initialize and free the audio routes */
struct audio_route *audio_route_init(unsigned int card, const char *xml_path);
void audio_route_free(struct audio_route *ar);

/* Apply an audio route path by name */
int audio_route_apply_path(struct audio_route *ar, const char *name);

/* Apply and update mixer with audio route path by name */
int audio_route_apply_and_update_path(struct audio_route *ar, const char *name);

/* Reset an audio route path by name */
int audio_route_reset_path(struct audio_route *ar, const char *name);

/* Reset and update mixer with audio route path by name */
int audio_route_reset_and_update_path(struct audio_route *ar, const char *name);

/* Reset and update mixer with audio route path by name forcely */
int audio_route_force_reset_and_update_path(struct audio_route *ar, const char *name);

/* Reset the audio routes back to the initial state */
void audio_route_reset(struct audio_route *ar);

/* Update the mixer with any changed values */
int audio_route_update_mixer(struct audio_route *ar);

#ifdef __ANDROID_VNDK_SEC__
/* Reset and apply and then update mixer with audio route path by names */
int audio_route_exchange_and_update_path(struct audio_route *ar,
        const char **reset_paths, unsigned int reset_count,
        const char **apply_paths, unsigned int apply_count);

/* select order of update mixer between the legacy and the order listed in the XML file  */
void audio_route_update_mixer_by_path(struct audio_route *ar, bool set);

/* Update mixer with audio route path which was requested by audio_route_apply_path() and audio_route_reset_path() */
int audio_route_update_mixer_path(struct audio_route *ar);

/* Get pcm-dai information */
int get_dai_link(struct audio_route *ar, enum pcm_dai_link dai_link);

/* Apply an audio route path (should contain only single control) by name & set the value */
int audio_route_apply_path_value(struct audio_route *ar, const char *name, long value);

/* return number of missing control */
int audio_route_missing_ctl(struct audio_route *ar);
#endif

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif
