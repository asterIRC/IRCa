/*
 * Override WHOIS logic to hide channel memberships that are not common.
 *   -- kaniini
 * But only for people who asked for this mistreatment.
 *   -- Reinhilde
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "hook.h"
#include "ircd.h"
#include "send.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "channel.h"
#include "s_user.h"

#define UMODE_SHOWONLYCOMCHANS_MODE_IN_USE  'I'

int _modinit(void) {
	user_modes[UMODE_SHOWONLYCOMCHANS_MODE_IN_USE] = find_umode_slot();
	user_mode_names[UMODE_SHOWONLYCOMCHANS_MODE_IN_USE] = "showonlycomchans";
	construct_umodebuf();
	return 0;
}

void _moddeinit(void) {
	user_modes[UMODE_SHOWONLYCOMCHANS_MODE_IN_USE] = 0;
	user_mode_names[UMODE_SHOWONLYCOMCHANS_MODE_IN_USE] = NULL;
	construct_umodebuf();
}

#define IsChanInvisible(user) ((user)->umodes & user_modes[UMODE_SHOWONLYCOMCHANS_MODE_IN_USE])

static void
h_uhuc_doing_whois_channel_visibility(hook_data_client *hdata)
{
	hdata->approved = ((PubChannel(hdata->chptr) && !IsChanInvisible(hdata->target)) || IsMember((hdata->client), (hdata->chptr)));
}

mapi_hfn_list_av1 huc_hfnlist[] = {
	{ "doing_whois_channel_visibility", (hookfn) h_uhuc_doing_whois_channel_visibility },
	{ NULL, NULL }
};

DECLARE_MODULE_AV1(umode_huc, _modinit, _moddeinit, NULL, NULL, huc_hfnlist, "version 1.0 of +I (hide channels you sharen't with a whoiser)");
