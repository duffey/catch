#include <curl/curl.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define DIR_MASK (S_IWGRP | S_IWOTH)
#define DIR_MODE (FILE_MODE | S_IXUSR | S_IXGRP | S_IXOTH)
#define	FILE_MASK (DIR_MASK | S_IXUSR | S_IXGRP | S_IXOTH)
#define	FILE_MODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define SREAD "Failed to read requested number of bytes"

struct item {
	char *filepath;
	char *dirpath;
	char *title;
	char *url;
	char *description;
	char *date;
	time_t time;
	struct item *left;
	struct item *right;
};

static char *format = "%-*f %t\n";
static char *prog;
static char *command;
struct item *root;
static int accessed;
static int unaccessed;
static int downloaded;
static int ndownloaded;
static int nitems;
static int current_item;
static size_t max_title;
static size_t max_url;
static size_t max_desc;
static size_t max_date;
static size_t max_filepath;

static void err_exit(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

static void free_items(struct item *root)
{
	if (root == NULL)
		return;
	free_items(root->left);
	free_items(root->right);
	free(root->filepath);
	free(root->dirpath);
	free(root->title);
	free(root->url);
	free(root->description);
	free(root->date);
	free(root);
}

static char *read_file(const char *filepath, size_t *size)
{
	struct stat stbuf;
	int fd;
	int fail;
	char *buf;

	if (stat(filepath, &stbuf) < 0)
		return NULL;
	if ((fd = open(filepath, O_RDONLY, 0)) < 0)
		return NULL;
	if ((buf = malloc(stbuf.st_size + 1)) == NULL) {
		close(fd);
		return NULL;
	}
	fail = read(fd, buf, stbuf.st_size) != stbuf.st_size;
	if (close(fd) < 0 || fail) {
		free(buf);
		return NULL;
	}
	buf[stbuf.st_size] = '\0';
	if (size != NULL)
		*size = stbuf.st_size;
	return buf;
}

static int dofilepath(const char *filepath, int isdir)
{
	struct stat stbuf;
	struct item *ip;
	struct item **ipp;
	struct tm time;
	static struct item **last = &root;
	int i;
	int r;
	int isaccessed;
	int isdownloaded;
	char *filename;
	char *meta_filepath = NULL;
	char *s = NULL;
	char *format[] = { "%a%n,%n%d%n%b%n%y%n%T", "%d%n%b%n%y%n%T"
		, "%a%n,%n%d%n%b%n%Y%n%T", "%d%n%b%n%Y%n%T"
		, "%a%n,%n%d%n%b%n%y%n%R", "%d%n%b%n%y%n%R"
		, "%a%n,%n%d%n%b%n%Y%n%R", "%d%n%b%n%Y%n%R" };
	size_t size;
	size_t tl;
	size_t ul;
	size_t dl;
	size_t l;

	errno = 0;
	if ((ip = calloc(1, sizeof(*ip))) == NULL)
		goto error;
	if ((ip->filepath = strdup(filepath)) == NULL)
		goto error;
	if ((ip->dirpath = strdup(dirname(ip->filepath))) == NULL)
		goto error;
	free(ip->filepath);
	if ((ip->filepath = strdup(filepath)) == NULL)
		goto error;
	filename = basename(ip->filepath);
	if ((meta_filepath = malloc(strlen(ip->dirpath) + strlen(filename)
		+ sizeof("/.catch/.meta"))) == NULL)
		goto error;
	if (sprintf(meta_filepath, "%s/.catch/%s.meta", ip->dirpath, filename)
		< 0)
		goto error;
	free(ip->filepath);
	if ((ip->filepath = strdup(filepath)) == NULL)
		goto error;
	if (access(meta_filepath, F_OK) < 0 && errno == ENOENT) {
		free_items(ip);
		if (!isdir)
			fprintf(stderr, "%s: %s: %s\n", prog, meta_filepath
				, strerror(errno));
		free(meta_filepath);
		return -1;
	}
	if ((r = stat(ip->filepath, &stbuf)) < 0 && r != ENOENT)
		goto error;
	isdownloaded = r == 0 && stbuf.st_size > 0;
	/* Ignore nanoseconds. */
	isaccessed = r == 0 && stbuf.st_atime > stbuf.st_mtime;
	if ((downloaded && !isdownloaded) || (ndownloaded && isdownloaded)
		|| (accessed && !isaccessed) || (unaccessed && isaccessed)) {
		free_items(ip);
		free(meta_filepath);
		return 0;
	}
	if ((s = read_file(meta_filepath, &size)) == NULL) {
		free_items(ip);
		fprintf(stderr, "%s: %s: %s\n", prog, meta_filepath, errno == 0
			? SREAD : strerror(errno));
		free(meta_filepath);
		return -2;
	}
	if ((ip->title = strdup(s)) == NULL
		|| (tl = strlen(ip->title)) == size
		|| (ip->url = strdup(s + tl + 1)) == NULL
		|| tl + (ul = strlen(ip->url)) + 1 == size
		|| (ip->description = strdup(s + tl + ul + 2)) == NULL
		|| tl + ul + (dl = strlen(ip->description)) + 2 == size
		|| (ip->date = strdup(s + tl + ul + dl + 3)) == NULL)
		goto error;
	for (i = 0; i < sizeof(format) / sizeof(*format); i++)
		if (strptime(ip->date, format[i], &time) != NULL) {
			if ((ip->time = mktime(&time)) < 0)
				goto error;
			break;
		}
	max_title = (l = strlen(ip->title)) > max_title ? l : max_title;
	max_url = (l = strlen(ip->url)) > max_url ? l : max_url;
	max_desc = (l = strlen(ip->description)) > max_desc ? l : max_desc;
	max_date = (l = strlen(ip->date)) > max_date ? l : max_date;
	max_filepath = (l = strlen(filepath)) > max_filepath ? l : max_filepath;
	free(meta_filepath);
	free(s);
	nitems++;
	/* Don't sort. */
	if (strcmp(command, "list") != 0) {
		*last = ip;
		last = &ip->right;
		return 0;
	}
	ipp = &root;
	while(*ipp != NULL) {
		r = strcmp(ip->dirpath, (*ipp)->dirpath);
		ipp = r < 0 || (r == 0 && (ip->time > (*ipp)->time
			|| (ip->time == (*ipp)->time
			&& strcmp(ip->filepath, (*ipp)->filepath) < 0)))
			? &(*ipp)->left : &(*ipp)->right;
	}
	*ipp = ip;
	return 0;
	error:
		if (errno != 0)
			perror(prog);
		else
			fprintf(stderr, "%s: %s: Parse failed\n", prog
				, meta_filepath);
		free(meta_filepath);
		free(s);
		free_items(ip);
		return -2;
}

static size_t write_data(void *buf, size_t size, size_t nmemb, void *userp)
{
	int *pfd = userp;
	ssize_t n;

	n = write(*pfd, buf, size * nmemb);
	return n < 0 ? 0 : n;
}

static int progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow
	, curl_off_t ultotal, curl_off_t ulnow)
{
	if (dltotal != 0)
		printf("\rDownloading %-*s (%d/%d): %3ld%% (%.1f MB/%.1f MB)"
			, (int) max_filepath, (char *) clientp, current_item
			, nitems, (long) (100L * dlnow / dltotal)
			, dlnow / 1048576.f, dltotal / 1048576.f);
	fflush(stdout);
	return 0;
}
	
static int download(const char *filepath, const char *url, int noprogress)
{
	int fd;
	CURL *curl;
	CURLcode res;

	if ((fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE)) < 0)
		return -1;
	if ((curl = curl_easy_init()) == NULL) {
		close(fd);
		return -1;
	}
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &fd);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, noprogress);
	curl_easy_setopt(curl, CURLOPT_XFERINFODATA, filepath);
	curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
	if((res = curl_easy_perform(curl)) != CURLE_OK)
		fprintf(stderr, "curl_easy_perform() failed: %s\n"
			, curl_easy_strerror(res));
	curl_easy_cleanup(curl);
	curl_global_cleanup();
	if (close(fd) < 0 || res != CURLE_OK)
		return -1;
	return 0;
}

static void traverse(const struct item *root)
{
	static char s[2];
	char *pf;
	int p = 0;
	int bs = 0;
	int a = 0;
	int m = 0;

	if (root == NULL)
		return;
	traverse(root->left);
	if (strcmp(command, "list") == 0) {
		for (pf = format; *pf != '\0'; pf++) {
			*s = *pf;
			if (printf("%*s",
				/* justification and maximum field width */
				(m ? -1 : 1) * (int) (a == 1
				? (*pf == 't' ? max_title
				: *pf == 'u' ? max_url
				: *pf == 'd' ? max_desc
				: *pf == 'p' ? max_date
				: *pf == 'f' ? max_filepath
				: 0) : 0),
				/* string/character */
				*pf == 'n' && bs ? "\n"
				: *pf == 't' && bs ? "\t"
				: *pf == 't' && p ? root->title
				: *pf == 'u' && p ? root->url
				: *pf == 'd' && p ? root->description
				: *pf == 'p' && p ? root->date
				: *pf == 'f' && p ? root->filepath
				: *pf == '%' ? (p ? "%" : "")
				: *pf == '\\' ? (bs ? "\\" : "")
				: *pf == '*' ? (p ? "" : "*")
				: *pf == '-' ? (p ? "" : "-")
				: s) < 0)
				err_exit("%s: %s\n", prog, strerror(errno));
			p = *pf == '%' ? !p : p && (*pf == '*' || *pf == '-');
			bs = *pf == '\\' && !bs;
			a = *pf == '*' || (p && a);
			m = *pf == '-' || (p && m);
		}
	} else {
		current_item++;
		if (download(root->filepath, root->url, 0L) < 0)
			err_exit("%s: %s: download failed\n", prog
				, root->filepath);
		putchar('\n');
	}
	traverse(root->right);
}

/* libxml2 handles xmlFree(NULL) and xmlXPathFreeObject(NULL),
 * but this is undocumented.
 */
static int parse_rss2(const char *dirpath, const char *filepath)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr node;
	xmlNodePtr title_node;
	xmlNodePtr desc_node;
	xmlNodePtr date_node;
	xmlNodePtr url_node;
	xmlChar *contents;
	xmlXPathContextPtr context;
	xmlXPathObjectPtr obj = NULL;
	int i;
	int r = 0;
	int fd;
	struct item *ip = NULL;
	char *urlcpy = NULL;
	char *filename;
	char *meta_filepath = NULL;
	FILE *fp;

	xmlInitParser();
	if ((doc = xmlParseFile(filepath)) == NULL)
		goto error;
	if ((context = xmlXPathNewContext(doc)) == NULL)
		goto error;
	obj = xmlXPathEvalExpression((xmlChar *) "/rss/channel/item", context);
	xmlXPathFreeContext(context);
	if (obj == NULL)
		goto error;
	if (xmlXPathNodeSetIsEmpty(obj->nodesetval))
		goto error;
	for (i = 0; i < obj->nodesetval->nodeNr; i++) { 
		title_node = NULL;
		desc_node = NULL;
		date_node = NULL;
		url_node = NULL;
		node = obj->nodesetval->nodeTab[i]->xmlChildrenNode;
		for (; node != NULL; node = node->next)
			if (!xmlStrcmp(node->name, (xmlChar *) "title"))
				title_node = node;
			else if (!xmlStrcmp(node->name,
				(xmlChar *) "description"))
				desc_node = node;
			else if (!xmlStrcmp(node->name, (xmlChar *) "pubDate"))
				date_node = node;
			else if (!xmlStrcmp(node->name,
				(xmlChar *) "enclosure"))
				url_node = node;
		if (url_node == NULL)
			continue;
		/* Prepare and write item to file. */
		if ((ip = calloc(1, sizeof(*ip))) == NULL)
			goto error;
		if ((contents = xmlGetProp(url_node, (xmlChar *) "url"))
			== NULL)
			goto error;
		if ((ip->url = strdup((char *) contents)) == NULL)
			goto error;
		xmlFree(contents);
		if (title_node != NULL && (contents = xmlNodeListGetString(doc,
			title_node->xmlChildrenNode, 1)) != NULL) {
			ip->title = strdup((char *) contents);
			xmlFree(contents);
			if (ip->title == NULL)
				goto error;
		}
		if (desc_node != NULL && (contents = xmlNodeListGetString(doc,
			desc_node->xmlChildrenNode, 1)) != NULL) {
			ip->description = strdup((char *) contents);
			xmlFree(contents);
			if (ip->description == NULL)
				goto error;
		}
		if (date_node != NULL && (contents = xmlNodeListGetString(doc,
			date_node->xmlChildrenNode, 1)) != NULL) {
			ip->date = strdup((char *) contents);
			xmlFree(contents);
			if (ip->date == NULL)
				goto error;
		}
		if ((urlcpy = strdup(ip->url)) == NULL)
			goto error;
		filename = basename(urlcpy);
		if ((ip->filepath = malloc(strlen(dirpath)
			+ strlen(filename) + 2)) == NULL)
			goto error;
		if (sprintf(ip->filepath, "%s/%s", dirpath, filename) < 0)
			goto error;
		if ((meta_filepath = malloc(strlen(ip->filepath)
			+ sizeof(".catch/.meta"))) == NULL)
			goto error;
		if (sprintf(meta_filepath, "%s/.catch/%s.meta", dirpath
			, filename) < 0)
			goto error;
		if ((fp = fopen(meta_filepath, "w")) == NULL)
			goto error;
		if (fprintf(fp, "%s%c%s%c%s%c%s"
			, ip->title != NULL ? ip->title : "", '\0'
			, ip->url != NULL ? ip->url : "", '\0'
			, ip->description != NULL ? ip->description : "", '\0'
			, ip->date != NULL ? ip->date : "") < 0) {
			fclose(fp);
			goto error;
		}
		if (fclose(fp) < 0)
			goto error;
		/* Create empty download file if it doesn't exist. */
		if ((fd = open(ip->filepath, O_CREAT | O_EXCL, FILE_MODE)) < 0
			&& errno != EEXIST)
			goto error;
		if (fd >= 0 && close(fd) < 0)
			goto error;
		free_items(ip);
		free(urlcpy);
		free(meta_filepath);
		urlcpy = NULL;
		meta_filepath = NULL;
	}
	goto end;
	error:
		r = -1;
		free_items(ip);
		free(urlcpy);
		free(meta_filepath);
	end:
		xmlXPathFreeObject(obj);
		if (doc != NULL)
			xmlFreeDoc(doc);
		xmlCleanupParser();
		return r;
}

int main(int argc, char **argv)
{
	int c;
	int status = EXIT_SUCCESS;
	char *url;
	char *dirpath;
	char *dot[] = { ".", NULL };
	char *filepath;
	FILE *fp;
	DIR *dfd;
	struct dirent *dp;
	struct stat stbuf;

	prog = argv[0];
	if (argc < 2)
		err_exit("%s: missing command\n", prog);
	command = argv[1];
	*++argv = prog;
	while ((c = getopt(argc - 1, argv, "audnf:")) != -1)
		switch (c) {
		case 'a':
			accessed = 1;
			break;
		case 'u':
			unaccessed = 1;
			break;
		case 'd':
			downloaded = 1;
			break;
		case 'n':
			ndownloaded = 1;
			break;
		case 'f':
			format = optarg;
			break;
		default:
			exit(EXIT_FAILURE);
		}
	argv += optind;
	if (strcmp(command, "init") == 0) {
		if (*argv == NULL)
			err_exit("%s: missing URL\n", prog);
		url = *argv++;
		dirpath = *argv == NULL ? "." : *argv;
		umask(DIR_MASK);
		if (chdir(dirpath) < 0 && (mkdir(dirpath, DIR_MODE) < 0
			|| chdir(dirpath) < 0))
			err_exit("%s: %s: %s\n", prog, dirpath
				, strerror(errno));
		if (chdir(".catch") < 0 && (mkdir(".catch", DIR_MODE) < 0
			|| chdir(".catch") < 0))
			err_exit("%s: %s/.catch: %s\n", prog, dirpath
				, strerror(errno));
		umask(FILE_MASK);
		if ((fp = fopen("url", "w")) == NULL || fputs(url, fp) < 0
			|| fclose(fp) < 0)
			err_exit("%s: %s/.catch/url: %s\n", prog, dirpath
			, strerror(errno));
		exit(EXIT_SUCCESS);
	}
	if (*argv == NULL)
		argv = dot;
	if (strcmp(command, "sync") == 0) {
		umask(FILE_MASK);
		for (; *argv != NULL; argv++) {
			if ((filepath = malloc(strlen(*argv)
				+ sizeof("/.catch/feed.xml"))) == NULL)
				err_exit("%s: %s\n", prog, strerror(errno));
			strcat(strcpy(filepath, *argv), "/.catch/url");
			if ((url = read_file(filepath, NULL)) == NULL) {
				fprintf(stderr, "%s: %s: %s\n", prog, filepath
					, errno == 0 ? SREAD : strerror(errno));
				free(filepath);
				status = EXIT_FAILURE;
				continue;
			}
			strcat(strcpy(filepath, *argv), "/.catch/feed.xml");
			if (download(filepath, url, 1L) < 0) {
				free(url);
				free(filepath);
				status = EXIT_FAILURE;
				continue;
			}
			free(url);
			if (parse_rss2(*argv, filepath) < 0) {
				fprintf(stderr, "%s: %s: Parse failed\n", prog
					, filepath);
				status = EXIT_FAILURE;
			}
			if (remove(filepath) < 0) {
				fprintf(stderr, "%s: %s %s\n", prog, filepath
					, strerror(errno));
				free(filepath);
				exit(EXIT_FAILURE);
			}
			free(filepath);
		}
		exit(status);
	}
	if (strcmp(command, "download") != 0 && strcmp(command, "list") != 0)
		err_exit("%s: invalid command '%s'\n", prog, command);
	for (; *argv != NULL; argv++) {
		if (stat(*argv, &stbuf) < 0)
			err_exit("%s: %s: %s\n", prog, *argv, strerror(errno));
		if (!S_ISDIR(stbuf.st_mode)) {
			if (dofilepath(*argv, S_ISDIR(stbuf.st_mode)) < -1)
				exit(EXIT_FAILURE);
			continue;
		}
		if ((dfd = opendir(*argv)) == NULL)
			err_exit("%s: %s: %s\n", prog, *argv, strerror(errno));
		while ((dp = readdir(dfd)) != NULL) {
			filepath = NULL;
			if ((filepath = malloc(strlen(*argv)
				+ strlen(dp->d_name) + 2)) == NULL
				|| sprintf(filepath, "%s/%s", *argv, dp->d_name)
				< 0) {
				closedir(dfd);
				free(filepath);
				err_exit("%s: %s\n", prog, strerror(errno));
			}
			if (dofilepath(filepath, S_ISDIR(stbuf.st_mode)) < -1) {
				closedir(dfd);
				free(filepath);
				exit(EXIT_FAILURE);
			}
			free(filepath);
		}
		if (closedir(dfd) < 0)
			err_exit("%s: %s\n", prog, strerror(errno));
	}
	traverse(root);
	free_items(root);
	exit(status);
}
