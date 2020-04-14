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
 * prototypes of CLI processing.
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
#include <rte_common.h>

#include "dp_stats.h"
#include "dp_commands.h"

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
	if (
		(!strcmp(res->keyword, "s")) || (!strcmp(res->keyword, "st")) ||
		(!strcmp(res->keyword, "sm")) || (!strcmp(res->keyword, "se"))
	  ) {
		/* Toggle sesstats_flg */
		if (sesstats_flg == 0) {
			sesstats_flg = 1;
			rfrsh_sstats = 1;        /* Flag new line for sesstats print */
			pktstats_flg = 0;        /* Disable pktstats */
			trfstats_flg = 0;        /* Disable traffic stats */
			mbfstats_flg = 0;        /* Disable memory stats */
			cmdline_printf(ngicdp_cl, "Enabled sesstats\n");
			/* Default sesstat_idx = TOP */
			sesstat_idx = TOP;
			if (!strcmp(res->keyword, "sm")) {
				sesstat_idx = MIDDLE;
			} else if (!strcmp(res->keyword, "se")) {
				sesstat_idx = END;
			}
		} else if (sesstats_flg == 1) {
			sesstats_flg = 0;
			rfrsh_sstats = 0;
			cmdline_printf(ngicdp_cl, "Disabled sesstats\n");
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
 * CLI command- show pktstats
 **/
struct cmd_pktstats_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_pktstats =
TOKEN_STRING_INITIALIZER(struct cmd_pktstats_result, keyword, "p");

static void cmd_show_pktstats(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	RTE_SET_USED(parsed_result);
	/* Toggle pktstats_flg */
	if (pktstats_flg == 0) {
		pktstats_flg = 1;
		rfrsh_pstats = 1;                /* Flag new line for pktstats print */
		sesstats_flg = 0;                /* Disable sesstats */
		trfstats_flg = 0;                /* Disable traffic stats */
		mbfstats_flg = 0;                /* Disable memory stats */
		cmdline_printf(ngicdp_cl, "Enabled pktstats\n");
		prn_pktstat_hdrs();
	} else if (pktstats_flg == 1) {
		pktstats_flg = 0;
		rfrsh_pstats = 0;
		cmdline_printf(ngicdp_cl, "Disabled pktstats\n");
	}
}

cmdline_parse_inst_t cmd_obj_pktstats = {
	.f = cmd_show_pktstats, /* function to call */
	.data = NULL,           /* 2nd arg of func */
	.help_str = "Toggle pktstats",
	.tokens = {             /* token list, NULL terminated */
		(void *)&cmd_pktstats,
		NULL,
	},
};

/***************************************************************
 *  * CLI command- show trfstats
 *   **/
struct cmd_trfstats_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_trfstats =
TOKEN_STRING_INITIALIZER(struct cmd_trfstats_result, keyword, "d");

static void cmd_show_trfstats(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	RTE_SET_USED(parsed_result);
	/* Toggle trfstats_flg */
	if (trfstats_flg == 0) {
		trfstats_flg = 1;
		rfrsh_dstats = 1;                /* Flag new line for trfstats print */
		sesstats_flg = 0;                /* Disable sesstats */
		pktstats_flg = 0;                /* Disable pktstats */
		mbfstats_flg = 0;                /* Disable memory stats */
		cmdline_printf(ngicdp_cl, "Enabled trfstats\n");
	} else if (trfstats_flg == 1) {
		trfstats_flg = 0;
		rfrsh_dstats = 0;
		cmdline_printf(ngicdp_cl, "Disabled trfstats\n");
	}
}

cmdline_parse_inst_t cmd_obj_trfstats = {
	.f = cmd_show_trfstats, /* function to call */
	.data = NULL,           /* 2nd arg of func */
	.help_str = "Toggle trfstats",
	.tokens = {             /* token list, NULL terminated */
		(void *)&cmd_trfstats,
		NULL,
	},
};

/***************************************************************
 * CLI command- show memory stats
 **/
struct cmd_mbfstats_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_mbfstats =
TOKEN_STRING_INITIALIZER(struct cmd_mbfstats_result, keyword, "m");

static void cmd_show_mbfstats(void *parsed_result,
		__attribute__((unused)) struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	RTE_SET_USED(parsed_result);
	/* Toggle mbfstats_flg */
	if (mbfstats_flg == 0) {
		mbfstats_flg = 1;
		rfrsh_mstats = 1;                /* Flag new line for mnfstats print */
		pktstats_flg = 0;
		sesstats_flg = 0;                /* Disable sesstats */
		trfstats_flg = 0;                /* Disable traffic stats */
		cmdline_printf(ngicdp_cl, "Enabled mbfstats\n");
		prn_mbfstat_hdrs();
	} else if (mbfstats_flg == 1) {
		mbfstats_flg = 0;
		rfrsh_mstats = 0;
		cmdline_printf(ngicdp_cl, "Disabled mbfstats\n");
	}
}

cmdline_parse_inst_t cmd_obj_mbfstats = {
	.f = cmd_show_mbfstats, /* function to call */
	.data = NULL,           /* 2nd arg of func */
	.help_str = "Toggle mbfstats",
	.tokens = {             /* token list, NULL terminated */
		(void *)&cmd_mbfstats,
		NULL,
	},
};

/***************************************************************
 * CLI command- quit dp
 **/
struct cmd_quit_result {
	cmdline_fixed_string_t keyword;
};

cmdline_parse_token_string_t cmd_quit =
TOKEN_STRING_INITIALIZER(struct cmd_quit_result, keyword, "q");

static void cmd_quit_dp(void *parsed_result,
		struct cmdline *cl,
		__attribute__((unused)) void *data)
{
	char user_inp;
	int ret;

	RTE_SET_USED(parsed_result);
	RTE_SET_USED(cl);
	RTE_SET_USED(data);
	cmdline_stdin_exit(ngicdp_cl);
	printf("Quitting DP CLI...Enter:"
			"\n\tX= Exit DP"
			"\n\tAny other key= CLI prompt\n");
	ret = scanf("%c", &user_inp);
	if (ret != EOF && user_inp == 'X')
		rte_exit(0, NULL);
	else {
		sesstats_flg = 0;
		rfrsh_sstats = 0;
		sesstat_idx = TOP;
		pktstats_flg = 0;
		rfrsh_pstats = 0;
		trfstats_flg = 0;
		rfrsh_dstats = 0;
		mbfstats_flg = 0;
		rfrsh_mstats = 0;
	}
}

cmdline_parse_inst_t cmd_obj_quit = {
	.f = cmd_quit_dp,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "Quit DP CLI",
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
	cmdline_printf(ngicdp_cl, "Commands supported:"
			"\n\t- s= toggle session stats"
			"\n\t- p= toggle pktstats"
			"\n\t- d= toggle trfstats"
			"\n\t- m= toggle memory stats"
			"\n\t- q= quit CLI"
			"\n\t- h= help\n");
}

cmdline_parse_inst_t cmd_obj_help = {
	.f = cmd_show_help,  /* function to call */
	.data = NULL,      /* 2nd arg of func */
	.help_str = "pktstats help",
	.tokens = {        /* token list, NULL terminated */
		(void *)&cmd_help,
		NULL,
	},
};

/***************************************************************
 * CLI CONTEXT: List of instructions
 **/
cmdline_parse_ctx_t main_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_obj_sesstats,
	(cmdline_parse_inst_t *)&cmd_obj_pktstats,
	(cmdline_parse_inst_t *)&cmd_obj_trfstats,
	(cmdline_parse_inst_t *)&cmd_obj_mbfstats,
	(cmdline_parse_inst_t *)&cmd_obj_quit,
	(cmdline_parse_inst_t *)&cmd_obj_help,
	NULL,
};

/**************************************************************/
