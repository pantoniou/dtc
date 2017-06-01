/*
 * fdtdump.c - Contributed by Pantelis Antoniou <pantelis.antoniou AT gmail.com>
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <libfdt.h>
#include <libfdt_env.h>
#include <fdt.h>

#include "util.h"

#define FDT_MAGIC_SIZE	4
#define MAX_VERSION 17

#define ALIGN(x, a)	(((x) + ((a) - 1)) & ~((a) - 1))
#define PALIGN(p, a)	((void *)(ALIGN((unsigned long)(p), (a))))
#define GET_CELL(p)	(p += 4, *((const fdt32_t *)(p-4)))

static int width = 80;
static int shift = 4;

static const char *tagname(uint32_t tag)
{
	static const char * const names[] = {
#define TN(t) [t] = #t
		TN(FDT_BEGIN_NODE),
		TN(FDT_END_NODE),
		TN(FDT_PROP),
		TN(FDT_NOP),
		TN(FDT_END),
#undef TN
	};
	if (tag < ARRAY_SIZE(names))
		if (names[tag])
			return names[tag];
	return "FDT_???";
}

#define dumpf(fmt, args...) \
	do { if (debug) printf("// " fmt, ## args); } while (0)

static void print_prop(int col, const char *data, int len)
{
	int i, j, qlen, span, fit;
	const char *s;
	char c, buf[C2STR_BUF_MAX];

	/* no data, don't print */
	if (len == 0)
		return;

	printf(" = ");
	col += strlen(" = ");

	if (util_is_printable_string(data, len)) {
		s = data;
		j = col;
		do {
			qlen = util_quoted_strlen(s);
			if (s > data) {
				printf(",");
				j++;

				if (j + qlen > width - 1) {
					j = col;
					printf("\n%*s", col, "");
				} else {
					printf(" ");
					j++;
				}
			}

			/* print quoted string */
			putchar('\"');
			while ((c = *s++) != '\0' && util_c2str(c, buf, sizeof(buf)))
				printf("%s", buf);
			putchar('\"');

			j += qlen;
		} while (s < data + len);

	} else if ((len % 4) == 0) {
		const fdt32_t *cell = (const fdt32_t *)data;

		len /= 4;

		/* how many words can we fit? */
		fit = (width - 1 - col - 2) / 11;

		do {
			printf("<");
			span = len > fit ? fit : len;
			for (i = 0; i < span; i++)
				printf("0x%08x%s", fdt32_to_cpu(cell[i]),
						i < (span - 1) ? " " : "");
			cell += span;
			len -= span;
			printf(">");
			if (len > 0)
				printf(",\n%*s", col, "");
		} while (len > 0);
	} else {
		const unsigned char *p = (const unsigned char *)data;

		/* how many bytes can we fit? */
		fit = (width - 1 - col - 2) / 3;

		do {
			printf("[");
			span = len > fit ? fit : len;
			for (i = 0; i < span; i++)
				printf("%02x%s", *p++,
						i < span - 1 ? " " : "");
			len -= span;
			printf("]");
			if (len > 0)
				printf(",\n%*s", col, "");
		} while (len > 0);
	}
}

static void dump_blob(void *blob, bool debug)
{
	uintptr_t blob_off = (uintptr_t)blob;
	struct fdt_header *bph = blob;
	uint32_t off_mem_rsvmap = fdt32_to_cpu(bph->off_mem_rsvmap);
	uint32_t off_dt = fdt32_to_cpu(bph->off_dt_struct);
	uint32_t off_str = fdt32_to_cpu(bph->off_dt_strings);
	struct fdt_reserve_entry *p_rsvmap =
		(struct fdt_reserve_entry *)((char *)blob + off_mem_rsvmap);
	const char *p_struct = (const char *)blob + off_dt;
	const char *p_strings = (const char *)blob + off_str;
	uint32_t version = fdt32_to_cpu(bph->version);
	uint32_t totalsize = fdt32_to_cpu(bph->totalsize);
	uint32_t tag;
	const char *p, *s, *t;
	int depth, sz;
	int i;
	uint64_t addr, size;

	depth = 0;

	printf("/dts-v1/;\n");
	printf("// magic:\t\t0x%x\n", fdt32_to_cpu(bph->magic));
	printf("// totalsize:\t\t0x%x (%d)\n", totalsize, totalsize);
	printf("// off_dt_struct:\t0x%x\n", off_dt);
	printf("// off_dt_strings:\t0x%x\n", off_str);
	printf("// off_mem_rsvmap:\t0x%x\n", off_mem_rsvmap);
	printf("// version:\t\t%d\n", version);
	printf("// last_comp_version:\t%d\n",
	       fdt32_to_cpu(bph->last_comp_version));
	if (version >= 2)
		printf("// boot_cpuid_phys:\t0x%x\n",
		       fdt32_to_cpu(bph->boot_cpuid_phys));

	if (version >= 3)
		printf("// size_dt_strings:\t0x%x\n",
		       fdt32_to_cpu(bph->size_dt_strings));
	if (version >= 17)
		printf("// size_dt_struct:\t0x%x\n",
		       fdt32_to_cpu(bph->size_dt_struct));
	printf("\n");

	for (i = 0; ; i++) {
		addr = fdt64_to_cpu(p_rsvmap[i].address);
		size = fdt64_to_cpu(p_rsvmap[i].size);
		if (addr == 0 && size == 0)
			break;

		printf("/memreserve/ %#llx %#llx;\n",
		       (unsigned long long)addr, (unsigned long long)size);
	}

	p = p_struct;
	while ((tag = fdt32_to_cpu(GET_CELL(p))) != FDT_END) {

		dumpf("%04zx: tag: 0x%08x (%s)\n",
		        (uintptr_t)p - blob_off - 4, tag, tagname(tag));

		if (tag == FDT_BEGIN_NODE) {
			s = p;
			p = PALIGN(p + strlen(s) + 1, 4);

			if (*s == '\0')
				s = "/";

			printf("%*s%s {\n", depth * shift, "", s);

			depth++;
			continue;
		}

		if (tag == FDT_END_NODE) {
			depth--;

			printf("%*s};\n", depth * shift, "");
			continue;
		}

		if (tag == FDT_NOP) {
			printf("%*s// [NOP]\n", depth * shift, "");
			continue;
		}

		if (tag != FDT_PROP) {
			fprintf(stderr, "%*s ** Unknown tag 0x%08x\n",
					depth * shift, "", tag);
			break;
		}
		sz = fdt32_to_cpu(GET_CELL(p));
		s = p_strings + fdt32_to_cpu(GET_CELL(p));
		if (version < 16 && sz >= 8)
			p = PALIGN(p, 8);
		t = p;

		p = PALIGN(p + sz, 4);

		dumpf("%04zx: string: %s\n", (uintptr_t)s - blob_off, s);
		dumpf("%04zx: value\n", (uintptr_t)t - blob_off);
		printf("%*s%s", depth * shift, "", s);
		print_prop(depth * shift + strlen(s), t, sz);
		printf(";\n");
	}
}

/* Usage related data. */
static const char usage_synopsis[] = "fdtdump [options] <file>";
static const char usage_short_opts[] = "dsw:S:" USAGE_COMMON_SHORT_OPTS;
static struct option const usage_long_opts[] = {
	{"debug",            no_argument, NULL, 'd'},
	{"scan",             no_argument, NULL, 's'},
	{"width",	     required_argument, NULL, 'w' },
	{"shift",	     required_argument, NULL, 'S' },
	USAGE_COMMON_LONG_OPTS
};
static const char * const usage_opts_help[] = {
	"Dump debug information while decoding the file",
	"Scan for an embedded fdt in file",
	"Width of output",
	"Shift space amount when recursing",
	USAGE_COMMON_OPTS_HELP
};

static bool valid_header(char *p, off_t len)
{
	if (len < sizeof(struct fdt_header) ||
	    fdt_magic(p) != FDT_MAGIC ||
	    fdt_version(p) > MAX_VERSION ||
	    fdt_last_comp_version(p) > MAX_VERSION ||
	    fdt_totalsize(p) >= len ||
	    fdt_off_dt_struct(p) >= len ||
	    fdt_off_dt_strings(p) >= len)
		return 0;
	else
		return 1;
}

int main(int argc, char *argv[])
{
	int opt;
	const char *file;
	char *buf;
	bool debug = false;
	bool scan = false;
	off_t len;

	fprintf(stderr, "\n"
"**** fdtdump is a low-level debugging tool, not meant for general use.\n"
"**** If you want to decompile a dtb, you probably want\n"
"****     dtc -I dtb -O dts <filename>\n\n"
		);
	while ((opt = util_getopt_long()) != EOF) {
		switch (opt) {
		case_USAGE_COMMON_FLAGS

		case 'd':
			debug = true;
			break;
		case 's':
			scan = true;
			break;
		case 'w':
			width = atoi(optarg);
			break;
		case 'S':
			shift = atoi(optarg);
			break;
		}
	}
	if (optind != argc - 1)
		usage("missing input filename");
	file = argv[optind];

	buf = utilfdt_read_len(file, &len);
	if (!buf)
		die("could not read: %s\n", file);

	/* try and locate an embedded fdt in a bigger blob */
	if (scan) {
		unsigned char smagic[FDT_MAGIC_SIZE];
		char *p = buf;
		char *endp = buf + len;

		fdt_set_magic(smagic, FDT_MAGIC);

		/* poor man's memmem */
		while ((endp - p) >= FDT_MAGIC_SIZE) {
			p = memchr(p, smagic[0], endp - p - FDT_MAGIC_SIZE);
			if (!p)
				break;
			if (fdt_magic(p) == FDT_MAGIC) {
				/* try and validate the main struct */
				off_t this_len = endp - p;
				if (valid_header(p, this_len))
					break;
				if (debug)
					printf("%s: skipping fdt magic at offset %#zx\n",
						file, p - buf);
			}
			++p;
		}
		if (!p || endp - p < sizeof(struct fdt_header))
			die("%s: could not locate fdt magic\n", file);
		printf("%s: found fdt at offset %#zx\n", file, p - buf);
		buf = p;
	} else if (!valid_header(buf, len))
		die("%s: header is not valid\n", file);

	dump_blob(buf, debug);

	return 0;
}
