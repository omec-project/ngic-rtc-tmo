/*
 * Copyright (c) 2020 Intel Corporation
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the University of California, Berkeley nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of CLI processing in the CP.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <termios.h>
#ifndef __linux__
#ifdef __FreeBSD__
#include <sys/socket.h>
#else
#include <net/socket.h>
#endif
#endif

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <cmdline.h>

#include <rte_string_fns.h>

#include "cp_stats.h"
#include "cp_commands.h"

/**
 * Function to display CP session stats headers for CLI
 *
 * @param
 *	Void
 *
 * @return
 *	None
 */
static void
prn_uecontext_hdrs(void)
{
	char buf[MAX_CPDSP_LEN];

	printf("%.*s\n",MAX_CPDSP_LEN, (char *) memset(buf, '-', MAX_CPDSP_LEN));
	printf("%15s %16s %16s \n",
			"UE_IP", "IMSI", "MSISDN");
	printf("%.*s\n",MAX_CPDSP_LEN, (char *) memset(buf, '-', MAX_CPDSP_LEN));
}

/***************************************************************
 * CLI command- query imsi
 **/
struct cmd_queryimsi_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_queryimsi =
	TOKEN_STRING_INITIALIZER(struct cmd_queryimsi_result, keyword,
						"r");

static void cmd_show_queryimsi(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	uint8_t k;
	uint32_t ue_ip;
	uint64_t imsi;
	uint64_t msisdn;
	char user_inp[QUERY_SZ];
	char *user_inpend = NULL;
	int32_t ret, hash_res = 0;
	ue_context *context = NULL;

	RTE_SET_USED(parsed_result);
	/* Toggle queryimsi_flg */
	if (queryimsi_flg == 0) {
		queryimsi_flg = 1;
		sesstats_flg = 0;        /* Disable sesstats */
		ifistats_flg = 0;        /* Disable ifistats */
		msgstats_flg = 0;        /* Disable msgstats */
		cmdline_printf(ngiccp_cl, "Enabled queryimsi\n");
		printf("Query IMSI...Entry format:"
				"\n\t<imsi_val><CR>"
				"\n\tX= Exit Query IMSI\n");
		do {
			memset(user_inp, 0, QUERY_SZ);
			ret = scanf("%s", user_inp);
			if (ret != EOF && user_inp[0] != 'X') {
				printf("Querying imsi:\t%s;\t", user_inp);
				imsi = strtoll(user_inp, &user_inpend, 10);
				printf("UE Context imsi key= %lu\n", imsi);
				hash_res = rte_hash_lookup_data(ue_context_by_imsi_hash, &imsi,
						(void **) &(context));
				if(hash_res == -ENOENT) {
					printf("No UE Context @imsi= %lu\n", imsi);
				} else {
					prn_uecontext_hdrs();
					ue_ip = htonl(((ue_context *)context)->dp_session->ue_addr.u.ipv4_addr);
					imsi = ((ue_context *)context)->imsi;
//					*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) =
//						*((uint8_t *)(&imsi) + APN_IMSI_KEY_POSTN) >>
//						APN_IMSI_KEY_LEN | APN_IMSI_SHIFT_VAL;

					printf("%16s %16lu %2s",
							inet_ntoa(*(struct in_addr *)(&ue_ip)), imsi, " ");
					for (k = 0; k < BINARY_MSISDN_LEN; k++) {
						*((int8_t *)&msisdn + k) = *(int8_t *)(((ue_context *)context)->msisdn + k);
					}
					printf("%16lu\n", msisdn);
					printf("\n");
				}
			}
		} while (user_inp[0] != 'X');
	}
		queryimsi_flg = 0;
		cmdline_printf(ngiccp_cl, "Disabled queryimsi\n");
		cmdline_printf(ngiccp_cl, "Command options:"
				"\n\t- r= toggle request query"
				"\n\t- s= toggle session stats"
				"\n\t\t Session Table Index::"
				"\n\t\t\tst= TOP; sm= MIDDLE; se= END"
				"\n\t- i= toggle interface interaction stats (ifistats)"
				"\n\t- m= toggle msgstats"
				"\n\t- q= quit CLI"
				"\n\t- h= help\n");
				printf("\n");
}

cmdline_parse_inst_t cmd_obj_queryimsi = {
	.f = cmd_show_queryimsi, /* function to call */
	.data = NULL,           /* 2nd arg of func */
	.help_str = "Toggle session stats",
	.tokens = {             /* token list, NULL terminated */
		(void *)&cmd_queryimsi,
		NULL,
	},
};

/***************************************************************
 * CLI command- show session stats
 **/
struct cmd_sesstats_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_sesstats =
	TOKEN_STRING_INITIALIZER(struct cmd_sesstats_result, keyword,
						"s#st#sm#se");

static void cmd_show_sesstats(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	struct cmd_sesstats_result *res = parsed_result;
//	RTE_SET_USED(parsed_result);
	if (
		(!strcmp(res->keyword, "s")) || (!strcmp(res->keyword, "st")) ||
		(!strcmp(res->keyword, "sm")) || (!strcmp(res->keyword, "se"))
	  ) {
		/* Toggle sesstats_flg */
		if (sesstats_flg == 0) {
			sesstats_flg = 1;
			queryimsi_flg = 0;       /* Disable queryimsi */
			ifistats_flg = 0;        /* Disable ifistats */
			msgstats_flg = 0;        /* Disable msgstats */
			cmdline_printf(ngiccp_cl, "Enabled sesstats\n");
			/* Default sesstat_idx = TOP */
			sesstat_idx = TOP;
			if (!strcmp(res->keyword, "sm")) {
				sesstat_idx = MIDDLE;
			} else if (!strcmp(res->keyword, "se")) {
				sesstat_idx = END;
			}
		} else if (sesstats_flg == 1) {
			sesstats_flg = 0;
			cmdline_printf(ngiccp_cl, "Disabled sesstats\n");
		}
	}
}

cmdline_parse_inst_t cmd_obj_sesstats = {
	.f = cmd_show_sesstats, /* function to call */
	.data = NULL,           /* 2nd arg of func */
	.help_str = "Toggle session stats",
	.tokens = {             /* token list, NULL terminated */
		(void *)&cmd_sesstats,
		NULL,
	},
};

/***************************************************************
 * CLI command- show ifistats
 **/
struct cmd_ifistats_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_ifistats =
TOKEN_STRING_INITIALIZER(struct cmd_ifistats_result, keyword, "i");

static void cmd_show_ifistats(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	RTE_SET_USED(parsed_result);
	/* Toggle ifistats_flg */
	if (ifistats_flg == 0) {
		ifistats_flg = 1;
		rfrsh_istats = 1;                /* Flag new line for ifistats print */
		queryimsi_flg = 0;               /* Disable queryimsi */
		sesstats_flg = 0;                /* Disable sesstats */
		msgstats_flg = 0;                /* Disable msgstats */
		cmdline_printf(ngiccp_cl, "Enabled ifistats\n");
	} else if (ifistats_flg == 1) {
		ifistats_flg = 0;
		rfrsh_istats = 0;
		cmdline_printf(ngiccp_cl, "Disabled ifistats\n");
	}
}

cmdline_parse_inst_t cmd_obj_ifistats = {
	.f = cmd_show_ifistats, /* function to call */
	.data = NULL,           /* 2nd arg of func */
	.help_str = "Toggle ifistats",
	.tokens = {             /* token list, NULL terminated */
		(void *)&cmd_ifistats,
		NULL,
	},
};

/***************************************************************
 * CLI command- show msgstats
 **/
struct cmd_msgstats_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_msgstats =
TOKEN_STRING_INITIALIZER(struct cmd_msgstats_result, keyword, "m");

static void cmd_show_msgstats(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	RTE_SET_USED(parsed_result);
	/* Toggle msgstats_flg */
	if (msgstats_flg == 0) {
		msgstats_flg = 1;
		queryimsi_flg = 0;               /* Disable queryimsi */
		sesstats_flg = 0;                /* Disable sesstats */
		ifistats_flg = 0;                /* Disable ifistats */
		cmdline_printf(ngiccp_cl, "Enabled msgstats\n");
	} else if (msgstats_flg == 1) {
		msgstats_flg = 0;
		cmdline_printf(ngiccp_cl, "Disabled msgstats\n");
	}
}

cmdline_parse_inst_t cmd_obj_msgstats = {
	.f = cmd_show_msgstats, /* function to call */
	.data = NULL,           /* 2nd arg of func */
	.help_str = "Toggle msgstats",
	.tokens = {             /* token list, NULL terminated */
		(void *)&cmd_msgstats,
		NULL,
	},
};

/***************************************************************
 * CLI command- quit cp
 **/
struct cmd_quit_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_quit =
TOKEN_STRING_INITIALIZER(struct cmd_quit_result, keyword, "q");

static void cmd_quit_cp(void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	char user_inp;
	int ret;

	RTE_SET_USED(parsed_result);
	RTE_SET_USED(cl);
	RTE_SET_USED(data);
	cmdline_stdin_exit(ngiccp_cl);
	printf("Quitting CP CLI...Enter:"
			"\n\tX= Exit CP"
			"\n\tAny other key= CLI prompt\n");
	ret = scanf("%c", &user_inp);
	if (ret != EOF && user_inp == 'X')
		rte_exit(0, NULL);
	else {
		queryimsi_flg = 0;               /* Disable queryimsi */
		sesstats_flg = 0;                /* Disable sesstats */
		msgstats_flg = 0;                /* Disable msgstats */
	}
}

cmdline_parse_inst_t cmd_obj_quit = {
	.f = cmd_quit_cp,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "Quit CP CLI",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_quit,
		NULL,
	},
};

/***************************************************************
 * CLI command- show help
 **/
struct cmd_show_help_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_help =
TOKEN_STRING_INITIALIZER(struct cmd_show_help_result, keyword, "h");

static void cmd_show_help(__attribute__((unused)) void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	RTE_SET_USED(parsed_result);
	RTE_SET_USED(data);
	cmdline_printf(ngiccp_cl, "Commands supported:"
			"\n\t- r= toggle request query"
			"\n\t- s= toggle session stats"
			"\n\t\t Session Table Index::"
			"\n\t\t\tst= TOP; sm= MIDDLE; se= END"
			"\n\t- i= toggle interface interaction stats (ifistats)"
			"\n\t- m= toggle msgstats"
			"\n\t- q= quit CLI"
			"\n\t- h= help\n");
}

cmdline_parse_inst_t cmd_obj_help = {
	.f = cmd_show_help,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "msgstats help",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_help,
		NULL,
	},
};

/***************************************************************
 * CLI CONTEXT: List of instructions
 **/
cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_obj_queryimsi,
	(cmdline_parse_inst_t *)&cmd_obj_sesstats,
	(cmdline_parse_inst_t *)&cmd_obj_ifistats,
	(cmdline_parse_inst_t *)&cmd_obj_msgstats,
	(cmdline_parse_inst_t *)&cmd_obj_quit,
	(cmdline_parse_inst_t *)&cmd_obj_help,
	NULL,
};

/**************************************************************/
