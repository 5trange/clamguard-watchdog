#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <filesystem>
#include <fstream>

// ClamAV
#include "clamav.h"

using namespace std;
using namespace std::filesystem;
using std::string;


class Engine
{
public:

    int fd, ret;
    unsigned long int size = 0;
    unsigned int sigs = 0;
    long double mb;
    const char* virname;
    string filename_s;
    const char* filename;
    const char* filename_p;
    struct cl_stat dbstat;
    struct cl_engine* engine;
    struct cl_scan_options options;
 
    int init_libclamav()
    {
        cout << "Initializing libclamav..." << endl;
        if ((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS)
        {
            cout << "Error initializing libclamav! " << ret << endl;
            return 1;
        }
        else
        {
            cout << "Initialized libclamav." << endl;
            return 0;
        }
    }

    int create_engine()
    {
        if (!(engine = cl_engine_new()))
        {
            cout << "Error creating new engine!" << endl;
            return 1;
        }
        else
        {
            cout << "Created new engine." << endl;
            return 0;
        }
    }

    int print_datadir()
    {
        cout << "Hardcoded database directory: " << cl_retdbdir << endl;
        return 0;
    }

    int load_database()
    {
        cout << "Loading database..." << endl;
        unsigned int* dbcnt = 0;
        ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);
        if (ret == CL_SUCCESS)
        {
            // Prints the number of database files loaded.
            cout << "Database files loaded: " << cl_countsigs(cl_retdbdir(), CL_COUNTSIGS_ALL, dbcnt) << endl;
            return 0;
        }
        else
        {
            cout << "Error loading database!" << endl;
            return 1;
        }
    }

    int check_database()
    {
        memset(&dbstat, 0, sizeof(struct cl_stat));
        cl_statinidir(cl_retdbdir(), &dbstat);
        if (cl_statchkdir(&dbstat) == 1) 
        {
            cout << "Reloading database..." << endl;
            cl_statfree(&dbstat);
            cl_statinidir(cl_retdbdir(), &dbstat);
        }
        else
        {
            cout << "Database check passed." << endl;
        }
        return 0;
    }

    int compile_engine()
    {
        if ((ret = cl_engine_compile(engine)) != CL_SUCCESS)
        {
            cout << "Error at cl_engine_compile() : " << cl_strerror(ret) << endl;
            cl_engine_free(engine);
            return 1;
        }
        else
        {
            cout << "Engine compiled successfully." << endl;
            return 0;
        }
    }

    int scan_file(const char* filename)
    {
        memset(&options, 0, sizeof(struct cl_scan_options));

        // libclamav options
        options.general = CL_SCAN_GENERAL_ALLMATCHES | CL_SCAN_GENERAL_HEURISTICS;

        options.parse = CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF | CL_SCAN_PARSE_PDF |
            CL_SCAN_PARSE_SWF | CL_SCAN_PARSE_HWP3 | CL_SCAN_PARSE_XMLDOCS |
            CL_SCAN_PARSE_MAIL | CL_SCAN_PARSE_OLE2 | CL_SCAN_PARSE_HTML |
            CL_SCAN_PARSE_PE;

        options.heuristic = CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE |
            CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE |
            CL_SCAN_HEURISTIC_ENCRYPTED_DOC | CL_SCAN_HEURISTIC_BROKEN |
            CL_SCAN_HEURISTIC_EXCEEDS_MAX |
            CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH |
            CL_SCAN_HEURISTIC_PHISHING_CLOAK | CL_SCAN_HEURISTIC_MACROS |
            CL_SCAN_HEURISTIC_PARTITION_INTXN | CL_SCAN_HEURISTIC_STRUCTURED |
            CL_SCAN_HEURISTIC_STRUCTURED_SSN_NORMAL |
            CL_SCAN_HEURISTIC_STRUCTURED_SSN_STRIPPED;
        // End options
        struct stat s;
        if (stat(filename, &s) == 0)
        {
            if (s.st_mode & S_IFDIR)
            {
                cout << filename << " is a directory." << endl;
                try
                {
                    // https://docs.microsoft.com/en-us/cpp/standard-library/recursive-directory-iterator-class?view=msvc-160
                    for (recursive_directory_iterator next(path(filename), directory_options::skip_permission_denied), end; next != end; ++next)
                    {
                        filename_s = next->path().generic_string();
                        filename_p = filename_s.c_str();
                        cout << "Scanning " << filename_p << endl;
                        if ((ret = cl_scanfile(filename_p, &virname, NULL, engine, &options)) == CL_VIRUS)
                        {
                            cout << "Detected: " << virname << endl;
                        }
                    }
                }
                catch (const char* e)
                {
                    cerr << e << endl;
                }
            }
            else if (s.st_mode & S_IFREG)
            {
                cout << filename << " is a file." << endl;
                cout << "Scanning " << filename << endl;
                if ((ret = cl_scanfile(filename, &virname, NULL, engine, &options)) == CL_VIRUS)
                {
                    cout << "Detected: " << virname << endl;
                    return 1;
                }
            }
            else
            {
                cout << filename << " is something else." << endl;
            }
        }
        else
        {
            cout << "Error determining file type!" << endl;
        }
        return 0;
    }

    int destroy_engine()
    {
        cl_engine_free(engine);
        cout << "Destroyed engine." << endl;
        return 0;
    }
};
int main()
{
    Engine new_engine;
    new_engine.init_libclamav();
    new_engine.create_engine();
    new_engine.print_datadir();
    new_engine.load_database();
    // new_engine.check_database(); Check database.
    new_engine.compile_engine();
    new_engine.scan_file("D:/Programs");
    new_engine.destroy_engine();
    return 0;
}
