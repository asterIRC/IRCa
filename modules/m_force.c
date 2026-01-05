/* contrib/m_force.c
 * Copyright (C) 1996-2002 Hybrid Development Team
 * Copyright (C) 2004 ircd-ratbox Development Team
 * Maybe (C) Elemental-IRCd?
 * part of ircd-chatd in this modified form
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1.Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  2.Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  3.The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "stdinc.h"
#include "channel.h"
#include "chmode.h"
#include "class.h"
#include "client.h"
#include "common.h"
#include "match.h"
#include "ircd.h"
#include "hostmask.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "logger.h"
#include "send.h"
#include "hash.h"
#include "s_serv.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"

static int mo_forcejoin(struct Client *client_p, struct Client *source_p,
                        int parc, const char *parv[]);
static int me_svsjoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int me_nsjoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message forcejoin_msgtab = {
    "FORCEJOIN", 0, 0, 0, MFLG_SLOW,
    {mg_unreg, mg_not_oper, {mo_forcejoin, 3}, mg_ignore, mg_ignore, {mo_forcejoin, 3}}
};

struct Message svsjoin_msgtab = {
    "SVSJOIN", 0, 0, 0, MFLG_SLOW,
    {mg_unreg, mg_not_oper, {mo_forcejoin, 3}, mg_ignore, {me_svsjoin, 3}, {mo_forcejoin, 3}}
};

struct Message nsjoin_msgtab = {
    "NSJOIN", 0, 0, 0, MFLG_SLOW,
    {mg_unreg, mg_not_oper, {mo_forcejoin, 3}, mg_ignore, {me_nsjoin, 3}, {mo_forcejoin, 3}}
};

mapi_clist_av1 force_clist[] = { &forcejoin_msgtab, &svsjoin_msgtab, &nsjoin_msgtab, NULL };


static int h_can_create_channel;
static int h_channel_join;


mapi_hlist_av1 force_hlist[] = {
	{ "can_create_channel", &h_can_create_channel },
	{ "channel_join", &h_channel_join },
	{ NULL, NULL },
};

DECLARE_MODULE_AV1(force, NULL, NULL, force_clist, force_hlist, NULL, "$Revision$");


/* Check what we will forward to, without sending any notices to the user
 * -- jilles
 */
static struct Channel *
check_forward(struct Client *source_p, struct Channel *chptr,
	     char *key, int *err)
{
	int depth = 0, i;
	const char *next = NULL;

	/* The caller (m_join) is only interested in the reason
	 * for the original channel.
	 */
	if ((*err = can_join(source_p, chptr, key, &next)) == 0)
		return chptr;

	/* User is +Q, or forwarding disabled */
	if (IsNoForward(source_p) || !ConfigChannel.use_forward)
		return NULL;

	while (depth < 16)
	{
		if (next == NULL)
			return NULL;
		chptr = find_channel(next);
		/* Can only forward to existing channels */
		if (chptr == NULL)
			return NULL;
		/* Already on there, show original error message */
		if (IsMember(source_p, chptr))
			return NULL;
		/* Juped. Sending a warning notice would be unfair */
		if (hash_find_resv(chptr->chname))
			return NULL;
		/* Don't forward to +Q channel */
		if (chptr->mode.mode & MODE_DISFORWARD)
			return NULL;
		i = can_join(source_p, chptr, key, &next);
		if (i == 0)
			return chptr;
		depth++;
	}

	return NULL;
}

/* send_join_error()
 *
 * input	- client to send to, reason, channel name
 * output	- none
 * side effects - error message sent to client
 */
static void
send_join_error(struct Client *source_p, int numeric, const char *name)
{
	/* This stuff is necessary because the form_str macro only
	 * accepts constants.
	 */
	switch (numeric)
	{
#define NORMAL_NUMERIC(i)						\
		case i:							\
			sendto_one(source_p, form_str(i),		\
					me.name, source_p->name, name);	\
			break

		NORMAL_NUMERIC(ERR_BANNEDFROMCHAN);
		NORMAL_NUMERIC(ERR_INVITEONLYCHAN);
		NORMAL_NUMERIC(ERR_BADCHANNELKEY);
		NORMAL_NUMERIC(ERR_CHANNELISFULL);
		NORMAL_NUMERIC(ERR_NEEDREGGEDNICK);
		NORMAL_NUMERIC(ERR_THROTTLE);

		default:
			sendto_one_numeric(source_p, numeric,
					"%s :Cannot join channel", name);
			break;
	}
}

/*
 * m_forcejoin
 *      parv[1] = user to force
 *      parv[2] = channel to force them into
 */
static int
mo_forcejoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    struct Channel *chptr;
    int type;
    char mode;
    char sjmode;
    char *newch;
    hook_data_channel_activity hook_info;

    if(!IsOperAdmin(source_p) && MyClient(source_p)) {
		// Do not check remote forcejoin; from a server we trust it always.
        sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "admin");
        return 0;
    }

    if((hunt_server(client_p, source_p, ":%s FORCEJOIN %s %s", 1, parc, parv)) != HUNTED_ISME) {
        sendto_one_notice(source_p, ":*** Hunting SVSJOIN for %s to %s",
                         parv[1], parv[2]);
        return 0;
    }

    /* if target_p is not existant, print message
     * to source_p and bail - scuzzy
     */
    if((target_p = find_client(parv[1])) == NULL) {
        sendto_one(source_p, form_str(ERR_NOSUCHNICK), me.name, source_p->name, parv[1]);
        return 0;
    }

    if(!IsPerson(target_p))
        return 0;

    sendto_wallops_flags(UMODE_WALLOP, &me,
                         "FORCEJOIN called for %s %s by %s!%s@%s",
                         parv[1], parv[2], source_p->name, source_p->username, source_p->host);
    ilog(L_MAIN, "FORCEJOIN called for %s %s by %s!%s@%s",
         parv[1], parv[2], source_p->name, source_p->username, source_p->host);
    sendto_server(NULL, NULL, NOCAPS, NOCAPS,
                  ":%s WALLOPS :FORCEJOIN called for %s %s by %s!%s@%s",
                  me.name, parv[1], parv[2],
                  source_p->name, source_p->username, source_p->host);

    /* select our modes from parv[2] if they exist... (chanop) */
    if(*parv[2] == 'o') {
        type = CHFL_CHANOP;
        mode = 'o';
        sjmode = '@';
    } else if(*parv[2] == 'v') {
        type = CHFL_VOICE;
        mode = 'v';
        sjmode = '+';
    } else if(*parv[2] == 'q') {
        type = CHFL_MANAGER;
        mode = 'q';
        sjmode = '~';
    } else if(*parv[2] == 'y') {
        type = CHFL_OPERBIZ;
        mode = 'y';
        sjmode = '~';
    } else if(*parv[2] == 'a') {
        type = CHFL_SUPEROP;
        mode = 'a';
        sjmode = '&';
    } else if(*parv[2] == 'h') {
        type = CHFL_HALFOP;
        mode = 'h';
        sjmode = '%';
    } else {
        type = CHFL_PEON;
        mode = sjmode = '\0';
    }

    if(mode != '\0')
        parv[2]++;

    if((chptr = find_channel(parv[2])) != NULL) {
        if(IsMember(target_p, chptr)) {
            /* debugging is fun... */
            sendto_one_notice(source_p, ":*** Notice -- %s is already in %s",
                              target_p->name, chptr->chname);
            return 0;
        }

        add_user_to_channel(chptr, target_p, type);

        sendto_server(NULL, chptr, NOCAPS, NOCAPS,
                      type ? ":%s SJOIN %ld %s + :%c%s" : ":%s SJOIN %ld %s + :%s%s",
                      me.id, (long) chptr->channelts,
                      chptr->chname, type ? sjmode : "", target_p->id);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

        if(type)
            sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s +%c %s",
                                 me.name, chptr->chname, mode, target_p->name);

        if(chptr->topic != NULL) {
            sendto_one(target_p, form_str(RPL_TOPIC), me.name,
                       target_p->id, chptr->chname, chptr->topic);
            sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
                       me.name, source_p->name, chptr->chname,
                       chptr->topic_info, chptr->topic_time);
        }

        channel_member_names(chptr, target_p, 1, 0);
    } else {
        newch = LOCAL_COPY(parv[2]);
        if(!check_channel_name(newch)) {
            sendto_one(source_p, form_str(ERR_BADCHANNAME), me.name,
                       source_p->name, (unsigned char *) newch);
            return 0;
        }

        /* channel name must be valid */
        if(!IsChannelName(newch)) {
            sendto_one(source_p, form_str(ERR_BADCHANNAME), me.name,
                       source_p->name, (unsigned char *) newch);
            return 0;
        }

        /* newch can't be longer than CHANNELLEN */
        if(strlen(newch) > CHANNELLEN) {
            sendto_one_notice(source_p, ":Channel name is too long");
            return 0;
        }

        chptr = get_or_create_channel(target_p, newch, NULL);
	chptr->channelts = rb_current_time();
        add_user_to_channel(chptr, target_p, type);
	chptr->mode.mode |= ChannelHasModes(newch) ?
		ConfigChannel.autochanmodes :
		ConfigChannel.modelessmodes;
	const char *modes = channel_modes(chptr, &me);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

	sendto_channel_local(ONLY_CHANOPS, chptr, ":%s MODE %s %s",
		     me.name, chptr->chname, modes);

	sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
		      sjmode!=0 ? ":%s SJOIN %ld %s %s :%s%s" : ":%s SJOIN %ld %s %s :%s%s",
		      me.id, (long) chptr->channelts,
		      chptr->chname, modes, sjmode!=0 ? sjmode : "", target_p->id);
        target_p->localClient->last_join_time = rb_current_time();
        del_invite(chptr, target_p);

	if(chptr->topic != NULL)
	{
		sendto_one(target_p, form_str(RPL_TOPIC), me.name,
			   target_p->name, chptr->chname, chptr->topic);
			sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
			   me.name, target_p->name, chptr->chname,
			   chptr->topic_info, chptr->topic_time);
	}

	channel_member_names(chptr, target_p, 1, 0);
	hook_info.client = target_p;
	hook_info.chptr = chptr;
	hook_info.key = NULL;
	call_hook(h_channel_join, &hook_info);
        target_p->localClient->last_join_time = rb_current_time();

        /* we do this to let the oper know that a channel was created, this will be
         * seen from the server handling the command instead of the server that
         * the oper is on.
         */
        sendto_one_notice(source_p, ":*** Notice -- Creating channel %s", chptr->chname);
    }
    return 0;
}

/*
 * me_svsjoin - quiet forcejoin
 *      parv[1] = user to force
 *      parv[2] = channel to force them into
 */
static int
me_svsjoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    struct Channel *chptr;
    int type;
    char mode;
    char sjmode;
    char *newch;
    hook_data_channel_activity hook_info;

    if(!(source_p->flags & FLAGS_SERVICE)) {
        return 0;
    }

    /* if target_p is not existant, print message
     * to source_p and bail - scuzzy
     */
    if((target_p = find_client(parv[1])) == NULL) {
        return 0;
    }

    if(!IsPerson(target_p))
        return 0;

    if(!MyClient(target_p))
        return 0;

    /* select our modes from parv[2] if they exist... (chanop) */
    if(*parv[2] == 'o') {
        type = CHFL_CHANOP;
        mode = 'o';
        sjmode = '@';
    } else if(*parv[2] == 'v') {
        type = CHFL_VOICE;
        mode = 'v';
        sjmode = '+';
    } else if(*parv[2] == 'q') {
        type = CHFL_MANAGER;
        mode = 'q';
        sjmode = '~';
    } else if(*parv[2] == 'y') {
        type = CHFL_OPERBIZ;
        mode = 'y';
        sjmode = '~';
    } else if(*parv[2] == 'a') {
        type = CHFL_SUPEROP;
        mode = 'a';
        sjmode = '&';
    } else if(*parv[2] == 'h') {
        type = CHFL_HALFOP;
        mode = 'h';
        sjmode = '%';
    } else {
        type = CHFL_PEON;
        mode = sjmode = '\0';
    }

    if(mode != '\0')
        parv[2]++;

    if((chptr = find_channel(parv[2])) != NULL) {
        if(IsMember(target_p, chptr)) {
            /* debugging is fun... */
            return 0;
        }

        add_user_to_channel(chptr, target_p, type);

        sendto_server(NULL, chptr, NOCAPS, NOCAPS,
                      type ? ":%s SJOIN %ld %s + :%c%s" : ":%s SJOIN %ld %s + :%s%s",
                      me.id, (long) chptr->channelts,
                      chptr->chname, type ? sjmode : "", target_p->id);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

        if(type)
            sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s +%c %s",
                                 me.name, chptr->chname, mode, target_p->name);
    } else {
        newch = LOCAL_COPY(parv[2]);
        if(!check_channel_name(newch)) {
            return 0;
        }

        /* channel name must begin with & or # */
        if(!IsChannelName(newch)) {
            return 0;
        }

        /* newch can't be longer than CHANNELLEN */
        if(strlen(newch) > CHANNELLEN) {
            return 0;
        }

        chptr = get_or_create_channel(target_p, newch, NULL);
	chptr->channelts = rb_current_time();
        add_user_to_channel(chptr, target_p, type);
	chptr->mode.mode |= ChannelHasModes(newch) ?
		ConfigChannel.autochanmodes :
		ConfigChannel.modelessmodes;
	const char *modes = channel_modes(chptr, &me);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

	sendto_channel_local(ONLY_CHANOPS, chptr, ":%s MODE %s %s",
		     me.name, chptr->chname, modes);

	sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
		      type ? ":%s SJOIN %ld %s %s :%c%s" : ":%s SJOIN %ld %s %s :%s%s",
		      me.id, (long) chptr->channelts,
		      chptr->chname, modes, type ? sjmode : "", target_p->id);

    }
        target_p->localClient->last_join_time = rb_current_time();
    del_invite(chptr, target_p);

	if(chptr->topic != NULL)
	{
		sendto_one(target_p, form_str(RPL_TOPIC), me.name,
			   target_p->name, chptr->chname, chptr->topic);
			sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
			   me.name, target_p->name, chptr->chname,
			   chptr->topic_info, chptr->topic_time);
	}

	channel_member_names(chptr, target_p, 1, 0);
	hook_info.client = target_p;
	hook_info.chptr = chptr;
	hook_info.key = NULL;
	call_hook(h_channel_join, &hook_info);
    return 0;
}

/*
 * me_nsjoin - quiet forcejoin, checks access
 *      parv[1] = user to force
 *      parv[2] = channel to force them into
 *      parv[3] = channel's key
 */
static int
me_nsjoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
    struct Client *target_p;
    struct Channel *chptr, *chptr2;
    int type, i;
    char mode;
    char sjmode;
    char *newch, *key = NULL;
    hook_data_channel_activity hook_info;

    if(!(source_p->flags & FLAGS_SERVICE)) {
        return 0;
    }

	if (parc > 3)
		key = parv[3];

    /* if target_p is not existant, print message
     * to source_p and bail - scuzzy
     */
    if((target_p = find_client(parv[1])) == NULL) {
        return 0;
    }

    if(!IsPerson(target_p))
        return 0;

    if(!MyClient(target_p))
        return 0;

    /* select our modes from parv[2] if they exist... (chanop) */
    if(*parv[2] == 'o') {
        type = CHFL_CHANOP;
        mode = 'o';
        sjmode = '@';
    } else if(*parv[2] == 'v') {
        type = CHFL_VOICE;
        mode = 'v';
        sjmode = '+';
    } else if(*parv[2] == 'q') {
        type = CHFL_MANAGER;
        mode = 'q';
        sjmode = '~';
    } else if(*parv[2] == 'y') {
        type = CHFL_OPERBIZ;
        mode = 'y';
        sjmode = '~';
    } else if(*parv[2] == 'a') {
        type = CHFL_SUPEROP;
        mode = 'a';
        sjmode = '&';
    } else if(*parv[2] == 'h') {
        type = CHFL_HALFOP;
        mode = 'h';
        sjmode = '%';
    } else {
        type = CHFL_PEON;
        mode = sjmode = '\0';
    }

    if(mode != '\0')
        parv[2]++;

    if((chptr = find_channel(parv[2])) != NULL) {
        if(IsMember(target_p, chptr)) {
            /* debugging is fun... */
            return 0;
        }

		/* If check_forward returns NULL, they couldn't join and there wasn't a usable forward channel. */
		if(!(chptr2 = check_forward(target_p, chptr, key, &i)))
		{
			/* might be wrong, but is there any other better location for such?
			 * see extensions/chm_operonly.c for other comments on this
			 * -- dwr
			 */
			if(i != ERR_CUSTOM)
				send_join_error(target_p, i, parv[2]);
			return 0;
		}
		else if(chptr != chptr2)
			sendto_one_numeric(target_p, ERR_LINKCHANNEL, form_str(ERR_LINKCHANNEL), parv[2], chptr2->chname);

		chptr = chptr2;

        add_user_to_channel(chptr, target_p, type);

        sendto_server(NULL, chptr, NOCAPS, NOCAPS,
                      type ? ":%s SJOIN %ld %s + :%c%s" : ":%s SJOIN %ld %s + :%s%s",
                      me.id, (long) chptr->channelts,
                      chptr->chname, type ? sjmode : "", target_p->id);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

        if(type)
            sendto_channel_local(ALL_MEMBERS, chptr, ":%s MODE %s +%c %s",
                                 me.name, chptr->chname, mode, target_p->name);
    } else {
        newch = LOCAL_COPY(parv[2]);
        if(!check_channel_name(newch)) {
            return 0;
        }

        /* channel name must begin with & or # */
        if(!IsChannelName(newch)) {
            return 0;
        }

        /* newch can't be longer than CHANNELLEN */
        if(strlen(newch) > CHANNELLEN) {
            return 0;
        }

        chptr = get_or_create_channel(target_p, newch, NULL);
		chptr->channelts = rb_current_time();

        add_user_to_channel(chptr, target_p, type);
		chptr->mode.mode |= ChannelHasModes(newch) ?
		ConfigChannel.autochanmodes :
		ConfigChannel.modelessmodes;
		const char *modes = channel_modes(chptr, &me);

        sendto_channel_local(ALL_MEMBERS, chptr, ":%s!%s@%s JOIN :%s",
                             target_p->name, target_p->username,
                             target_p->host, chptr->chname);

		sendto_channel_local(ONLY_CHANOPS, chptr, ":%s MODE %s %s",
		     me.name, chptr->chname, modes);

		sendto_server(NULL, chptr, CAP_TS6, NOCAPS,
		      type ? ":%s SJOIN %ld %s %s :%c%s" : ":%s SJOIN %ld %s %s :%s%s",
		      me.id, (long) chptr->channelts,
		      chptr->chname, modes, type ? sjmode : "", target_p->id);

    }
    target_p->localClient->last_join_time = rb_current_time();
    del_invite(chptr, target_p);

	if(chptr->topic != NULL)
	{
		sendto_one(target_p, form_str(RPL_TOPIC), me.name,
			   target_p->name, chptr->chname, chptr->topic);
			sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
			   me.name, target_p->name, chptr->chname,
			   chptr->topic_info, chptr->topic_time);
	}

	channel_member_names(chptr, target_p, 1, 0);
	hook_info.client = target_p;
	hook_info.chptr = chptr;
	hook_info.key = NULL;
	call_hook(h_channel_join, &hook_info);
    return 0;
}
