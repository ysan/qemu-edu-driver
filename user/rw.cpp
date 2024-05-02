#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <iostream>
#include <string>
#include <cstdio>
#include <vector>
#include <sstream>
#include <fstream>


#define DUMP_PUTS_OFFSET        "  "
void dumper (const uint8_t *src, int src_len, bool print_ascii=true) {
	if ((!src) || (src_len <= 0)) {
		return;
	}

	int i = 0;
	int j = 0;
	int k = 0;

	while (src_len >= 16) {
		fprintf (stdout, "%s0x%08x: ", DUMP_PUTS_OFFSET, i);
		fprintf (
			stdout,
			"%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x",
			*(src+ 0), *(src+ 1), *(src+ 2), *(src+ 3), *(src+ 4), *(src+ 5), *(src+ 6), *(src+ 7),
			*(src+ 8), *(src+ 9), *(src+10), *(src+11), *(src+12), *(src+13), *(src+14), *(src+15)
		);

		if (print_ascii) {
			fprintf (stdout, "  |");
			k = 0;
			while (k < 16) {
				fprintf (
					stdout,
					"%c",
					(*(src+k)>0x1f) && (*(src+k)<0x7f) ? *(src+k) : '.'
				);
				++ k;
			}
		}

		fprintf (stdout, "|\n");

		src += 16;
		i += 16;
		src_len -= 16;
	}

	if (src_len) {
		fprintf (stdout, "%s0x%08x: ", DUMP_PUTS_OFFSET, i);
		while (j < 16) {
			if (j < src_len) {
				fprintf (stdout, "%02x", *(src+j));
				if (j == 7) {
					fprintf (stdout, "  ");
				} else if (j == 15) {

				} else {
					fprintf (stdout, " ");
				}

			} else {
				fprintf (stdout, "  ");
				if (j == 7) {
					fprintf (stdout, "  ");
				} else if (j == 15) {

				} else {
					fprintf (stdout, " ");
				}
			}

			++ j;
		}

		if (print_ascii) {
			fprintf (stdout, "  |");
			k = 0;
			while (k < src_len) {
				fprintf (stdout, "%c", (*(src+k)>0x20) && (*(src+k)<0x7f) ? *(src+k) : '.');
				++ k;
			}
			for (int i = 0; i < (16 - src_len); ++ i) {
				fprintf (stdout, " ");
			}
		}

		fprintf (stdout, "|\n");
	}
}

std::string ltrim (const std::string &s) {
	size_t start = s.find_first_not_of(" \n\r\t\f\v");
	return (start == std::string::npos) ? "" : s.substr(start);
}

std::string rtrim (const std::string &s) {
	size_t end = s.find_last_not_of(" \n\r\t\f\v");
	return (end == std::string::npos) ? "" : s.substr(0, end + 1);
}

std::string trim (const std::string &s) {
	return rtrim(ltrim(s));
}

std::vector<std::string> split(const std::string& s) {
	std::vector<std::string> r;
	std::stringstream ss(s);
	std::string token;
	while (ss >> token) {
		r.push_back(token);
	}
	return r;
}

void printhelp (void) {
	printf("commands:\n");
	printf("  r       : read BAR register.\n");
	printf("  w       : write BAR register.\n");
	printf("  rdma    : DMA from device.\n");
	printf("  wdma    : DMA to device.\n");
	printf("  seekdma : seek DMA position.\n");
}

bool rw (int fd_reg, int fd_dma, std::vector<std::string> &cmdlist) {
	std::string cmd = cmdlist[0];
	if (cmd == "r") {
		if (cmdlist.size() != 2) {
			printf("read BAR register.\n");
			printf("usage: %s addr\n", cmd.c_str());
			return true;
		}

		uint8_t reg = strtoul(cmdlist[1].c_str(), 0, 0);
		off_t off = lseek (fd_reg, reg, SEEK_SET);
		if (off < 0) {
			perror ("lseek");
			return false;
		}

//		printf ("offset %ld\n", off);
		uint32_t buf = 0;
		int r = read (fd_reg, &buf, sizeof(buf)); // 32bit read
		if (r < 0) {
			perror ("read");
			return false;
		}
		printf("0x%x\n", buf);

	} else if (cmd == "w") {
		if (cmdlist.size() != 3) {
			printf("write BAR register.\n");
			printf("usage: %s addr data\n", cmd.c_str());
			return true;
		}

		uint8_t reg = strtoul(cmdlist[1].c_str(), 0, 0);
		off_t off = lseek (fd_reg, reg, SEEK_SET);
		if (off < 0) {
			perror ("lseek");
			return false;
		}

//		printf ("offset %ld\n", off);
		uint32_t buf = strtoul(cmdlist[2].c_str(), 0, 0);
		int r = write (fd_reg, &buf, sizeof(buf)); // 32bit write
		if (r < 0) {
			perror ("write");
			return false;
		}

	} else if (cmd == "rdma") {
		if (cmdlist.size() != 2) {
			printf("DMA from device.\n");
			printf("usage: %s length\n", cmd.c_str());
			return true;
		}

//		char buf[4096] = {0};
		char *buf = NULL;
		posix_memalign((void **)&buf, 4096, cmdlist[1].length() + 4096);
		if (!buf) {
			perror ("posix_memalign");
			return false;
		}
		size_t len = strtoul(cmdlist[1].c_str(), 0, 0);
		int r = read (fd_dma, buf, len);
		if (buf) {
			free(buf);
		}
		if (r < 0) {
			perror ("read");
			return false;
		}
		dumper((const uint8_t*)buf, len);

	} else if (cmd == "wdma") {
		if (cmdlist.size() != 2) {
			printf("DMA to device.\n");
			printf("usage: %s data\n", cmd.c_str());
			printf("    data: If prefixed with 'file=', interpret as file path, otherwise as ASCII byte sequence.\n");
			return true;
		}

		int r = 0;
//		char buf[4096] = {0};
		char *buf = NULL;

		std::string fk = "file=";
		auto pos = cmdlist[1].find(fk, 0);
		if (pos == std::string::npos) {
			posix_memalign((void **)&buf, 4096, cmdlist[1].length() + 4096);
			if (!buf) {
				perror ("posix_memalign");
				return false;
			}
			memcpy (buf, cmdlist[1].c_str(), cmdlist[1].length());
			r = write (fd_dma, buf, cmdlist[1].length());
			if (r < 0) {
				perror ("write");
				return false;
			}

		} else {
			auto path = cmdlist[1].substr(fk.length());
			std::ifstream ifs(path.c_str(), std::ios::in);
			if (!ifs.is_open()) {
				perror ("fine not opened...");
				return false;
			}
			std::stringstream ss;
			ss << ifs.rdbuf();

			posix_memalign((void **)&buf, 4096, ss.str().size() + 4096);
			if (!buf) {
				perror ("posix_memalign");
				return false;
			}
			memcpy (buf, ss.str().c_str(), ss.str().size());
			r = write (fd_dma, buf, ss.str().size());
		}
		if (buf) {
			free(buf);
		}
		if (r < 0) {
			perror ("write");
			return false;
		}

	} else if (cmd == "seekdma") {
		if (cmdlist.size() != 3) {
			printf("seek DMA position.\n");
			printf("usage: %s whence offset\n", cmd.c_str());
			printf("    whence: set/cur/end\n");
			return true;
		}
		std::string s = cmdlist[1];
		int whence = 0;
		if (s == "set") {
			whence = SEEK_SET;
		} else if (s == "cur") {
			whence = SEEK_CUR;
		} else if (s == "end") {
			whence = SEEK_END;
		} else {
			printf("usage: %s whence off\n", cmd.c_str());
			printf("    whence: set/cur/end\n");
			return false;
		}
		off_t off = strtoul(cmdlist[2].c_str(), 0, 0);
		ssize_t sz = lseek (fd_dma, off, whence);
		if ((int)sz < 0) {
			perror ("lseek");
			return false;
		} else {
			printf ("offset %ld\n", sz);
		}

	} else if (cmd == "help") {
		printhelp();

	} else {
		return false;
	}

	return true;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		fprintf (stderr, "\nusage: %s <cdev_reg> <cdev_dma>\n\n", argv[0]);
		exit(1);
	}

	char *cdev_reg = strdup(argv[1]);
	char *cdev_dma = strdup(argv[2]);
//	off_t pagesize = sysconf(_SC_PAGESIZE);
	int fd_reg = 0;
	if ((fd_reg = open(cdev_reg, O_RDWR | O_SYNC)) == -1) {
		perror("open");
		exit(1);
	}
	int fd_dma = 0;
	if ((fd_dma = open(cdev_dma, O_RDWR | O_SYNC)) == -1) {
		perror("open");
		exit(1);
	}

	size_t reg_len = 0x200;
	void *map = mmap(NULL, reg_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd_reg, 0);
	if (!map) {
		perror("mmap");
		close(fd_reg);
		close(fd_dma);
		exit(1);
	}
	printf("mmapped at address %p.\n", map);
	{
		uint8_t reg = 0x0;
		uint8_t *off = (uint8_t*)map + reg;
		printf("0x%x\n", *((uint32_t*)off)); // 32bit read
	}
	{
		uint8_t reg = 0x4;
		uint8_t *off = (uint8_t*)map + reg;
		*(uint32_t*)off = 0xaa55cc33; // 32bit write
		printf("0x%x\n", *((uint32_t*)off)); // 32bit read
	}

	printhelp();
	std::cout << "console start." << std::endl;
	std::string in;
	while (true) {
		std::cout << "> ";
		std::getline(std::cin, in);
		std::string t = trim(in);
		if (t.empty()) {
			continue;
		}
		auto cmd = split(t);
		if (!rw(fd_reg, fd_dma, cmd)) {
			std::cout << "invalid command..." << std::endl;
		}
	}

	if (munmap(map, reg_len) == -1) {
		perror("munmap");
	}
	close(fd_reg);
	close(fd_dma);

	return 0;
}
