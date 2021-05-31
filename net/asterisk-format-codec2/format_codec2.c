/*
* This is free software, licensed under the GNU General Public License v2.
* See /LICENSE for more information.
*/

#include "asterisk.h"

#include "asterisk/mod_format.h"
#include "asterisk/module.h"
#include "asterisk/format_cache.h"

#include <codec2/codec2.h>

#define CODEC2_SAMPLES    160  /* consider codec2_samples_per_frame(.) */
#define CODEC2_FRAME_LEN  6    /* consider codec2_bits_per_frame(.)    */

const char c2_file_magic[3] = {0xc0, 0xde, 0xc2};

struct c2_header {
    char magic[3];
    char version_major;
    char version_minor;
    char mode;
    char flags;
};

static struct ast_frame *c2_read(struct ast_filestream *s, int *whennext)
{
	size_t res;

	/* Send a frame from the file to the appropriate channel */
	AST_FRAME_SET_BUFFER(&s->fr, s->buf, AST_FRIENDLY_OFFSET, CODEC2_FRAME_LEN);
	if ((res = fread(s->fr.data.ptr, 1, s->fr.datalen, s->f)) != s->fr.datalen) {
		if (res) {
			ast_log(LOG_WARNING, "Short read of %s data (expected %d bytes, read %zu): %s\n",
					ast_format_get_name(s->fr.subclass.format), s->fr.datalen, res,
					strerror(errno));
		}
		return NULL;
	}
	*whennext = s->fr.samples = CODEC2_SAMPLES;
	return &s->fr;
}

static int c2_rewrite(struct ast_filestream *fs, const char *comment)
{
	struct c2_header hdr;

	memcpy(hdr.magic, c2_file_magic, sizeof(c2_file_magic));
	hdr.mode = CODEC2_MODE_2400;
	hdr.version_major = CODEC2_VERSION_MAJOR;
	hdr.version_minor = CODEC2_VERSION_MINOR;
	hdr.flags = 0;

	if (fwrite(&hdr, 1, sizeof(hdr), fs->f) != sizeof(hdr))
		return -1;

	return 0;
}

static int c2_write(struct ast_filestream *fs, struct ast_frame *f)
{
	int res;
	if (f->datalen % CODEC2_FRAME_LEN) {
		ast_log(LOG_WARNING, "Invalid data length, %d, should be multiple of 50\n", f->datalen);
		return -1;
	}
	if ((res = fwrite(f->data.ptr, 1, f->datalen, fs->f)) != f->datalen) {
			ast_log(LOG_WARNING, "Bad write (%d): %s\n", res, strerror(errno));
			return -1;
	}
	return 0;
}

static int c2_seek(struct ast_filestream *fs, off_t sample_offset, int whence)
{
	long bytes;
	off_t min,cur,max,offset=0;
	min = 0;
	cur = ftello(fs->f);
	fseeko(fs->f, 0, SEEK_END);
	max = ftello(fs->f);

	bytes = CODEC2_FRAME_LEN * (sample_offset / CODEC2_SAMPLES);
	if (whence == SEEK_SET)
		offset = bytes;
	else if (whence == SEEK_CUR || whence == SEEK_FORCECUR)
		offset = cur + bytes;
	else if (whence == SEEK_END)
		offset = max - bytes;
	if (whence != SEEK_FORCECUR) {
		offset = (offset > max)?max:offset;
	}
	/* protect against seeking beyond begining. */
	offset = (offset < min)?min:offset;
	if (fseeko(fs->f, offset, SEEK_SET) < 0)
		return -1;
	return 0;
}

static int c2_trunc(struct ast_filestream *fs)
{
	int fd;
	off_t cur;

	if ((fd = fileno(fs->f)) < 0) {
		ast_log(AST_LOG_WARNING, "Unable to determine file descriptor for Codec 2 filestream %p: %s\n", fs, strerror(errno));
		return -1;
	}
	if ((cur = ftello(fs->f)) < 0) {
		ast_log(AST_LOG_WARNING, "Unable to determine current position in Codec 2 filestream %p: %s\n", fs, strerror(errno));
		return -1;
	}
	/* Truncate file to current length */
	return ftruncate(fd, cur);
}

static off_t c2_tell(struct ast_filestream *fs)
{
	off_t offset = ftello(fs->f);
	return offset / CODEC2_FRAME_LEN * CODEC2_SAMPLES;
}

static struct ast_format_def c2_f = {
	.name = "codec2",
	.exts = "c2",
	// TODO .open = c2_open,
	.rewrite = c2_rewrite,
	.write = c2_write,
	.seek = c2_seek,
	.trunc = c2_trunc,
	.tell = c2_tell,
	.read = c2_read,
	.buf_size = CODEC2_FRAME_LEN + AST_FRIENDLY_OFFSET,
};

static int load_module(void)
{
	c2_f.format = ast_format_codec2;
	if (ast_format_def_register(&c2_f))
		return AST_MODULE_LOAD_DECLINE;
	return AST_MODULE_LOAD_SUCCESS;
}

static int unload_module(void)
{
	return ast_format_def_unregister(c2_f.name);
}

AST_MODULE_INFO(ASTERISK_GPL_KEY, AST_MODFLAG_LOAD_ORDER, "Codec2 data",
	.support_level = AST_MODULE_SUPPORT_CORE,
	.load = load_module,
	.unload = unload_module,
	.load_pri = AST_MODPRI_APP_DEPEND
);
