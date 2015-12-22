#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BPF_SZ 80

struct program_options {
	const char *interface;
	int	    snaplen;
	int	    count;
	char  bpf_expr[BPF_SZ];
};

/* Deal with non-option arguments here */
static inline int
copy_non_option_args(int argc, char **argv, char *bpf_expr)
{
	size_t room = BPF_SZ;
	char *p = bpf_expr;

	while (optind < argc) {
		char *m;
		size_t sz;

		m = argv[optind++];
		sz = strlen(m);
		if (room < sz + 1)
			return -1;
		memcpy(p, m, sz);
		p += sz;
		*p++ = ' ';
	}
	p = '\0';

	return 0;
}

int
get_program_options(int argc, char **argv, struct program_options *opts)
{
	int c;
	struct program_options stopt;


	const struct option long_options[] = {
		{"interface", required_argument, 0,	'i'},
		{"snaplen",   required_argument, 0,	's'},
		{"count",     required_argument, 0,	'c'},
		{"version",   no_argument,	 0,	'v'},
		{"help",      no_argument,	 0,	'h'},
		{ } /* terminating entry */
	};

	opts = &stopt;

	while (1) {
		int option_index = 0;

		c = getopt_long(argc, argv, "i:s:c:vh",
				long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'i':
			opts->interface = optarg;
			printf("opt: %c: optarg: %s\n", c, optarg);
			break;

			/*
			 * TODO: take precaution against a possible
			 * integer overflow, read man 3 strtol e.g.
			 */
		case 's':
			opts->snaplen = atoi(optarg);
			printf("opt: %c: optarg: %s\n", c, optarg);
			break;

		case 'c':
			opts->count = atoi(optarg);
			printf("opt: %c: optarg: %s\n", c, optarg);
			break;

		case 'v':
			printf("opt: %c: optarg: %s\n", c, optarg);
			break;

		case 'h':
			printf("opt: %c: optarg: %s\n", c, optarg);
			break;

		case '?':
			/* getopt_long will have already printed an error */
			printf("opt: %c: optarg: %s\n", c, optarg);
			break;

		default:
			/* Not sure how to get here... */
			printf("opt: %c: optarg: %s\n", c, optarg);
			return -1;
		}
	}

	return copy_non_option_args(argc, argv, opts->bpf_expr);
}
