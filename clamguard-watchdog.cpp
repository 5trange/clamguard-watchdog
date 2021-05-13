#include <iostream>
#include <string>
#include <thread>
#include "include\clamav.h"
using namespace std;


class Engine
{
public:

    int fd, ret;
    unsigned long int size = 0;
    unsigned int sigs = 0;
    long double mb;
    const char* virname;
    const char* filename;
    struct cl_stat dbstat;
    struct cl_engine* engine;
    struct cl_scan_options options;
 
    int init_libclamav()
    {
        if ((ret = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS)
        {
            cout << "\n\nError initializing libclamav! " << ret;
            return 1;
        }
        else
        {
            cout << "\n\nInitialized libclamav.";
            return 0;
        }
    }

    int create_engine()
    {
        if (!(engine = cl_engine_new()))
        {
            printf("\n\nError creating new engine!");
            return 1;
        }
        else
        {
            cout << "\n\nCreated new engine.";
            return 0;
        }
    }

    int print_datadir()
    {
        cout << "\n\nHardcoded database directory: " << cl_retdbdir;
        return 0;
    }

    int load_database()
    {
        cout << "\n\nLoading database...\n";
        unsigned int* dbcnt = 0;
        ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT);
        if (ret == CL_SUCCESS)
        {
            // Prints the number of database files loaded.
            cout << "\n\nDatabase files loaded: " << cl_countsigs(cl_retdbdir(), CL_COUNTSIGS_ALL, dbcnt);
            return 0;
        }
        else
        {
            cout << "\n\nError loading database!";
            return 1;
        }
    }

    int check_database()
    {
        memset(&dbstat, 0, sizeof(struct cl_stat));
        cl_statinidir(cl_retdbdir(), &dbstat);
        if (cl_statchkdir(&dbstat) == 1) 
        {
            cout << "\n\nReloading database...";
            cl_statfree(&dbstat);
            cl_statinidir(cl_retdbdir(), &dbstat);
        }
        else
        {
            cout << "\n\nDatabase check passed.";
        }
        return 0;
    }

    int compile_engine()
    {
        if ((ret = cl_engine_compile(engine)) != CL_SUCCESS)
        {
            cout << "\n\nError at cl_engine_compile() : " << cl_strerror(ret);
            cl_engine_free(engine);
            return 1;
        }
        else
        {
            cout << "\n\nEngine compiled successfully.";
            return 0;
        }
    }

    int scan_file(const char* filename)
    {
        cout << "\n\nScanning " << filename;
        memset(&options, 0, sizeof(struct cl_scan_options));
        options.parse |= ~0;
        options.general |= CL_SCAN_GENERAL_HEURISTICS;
        try
        {
            if ((ret = cl_scanfile(filename, &virname, NULL, engine, &options)) == CL_VIRUS) 
            {
                cout << "\n\nVirus detected: " << virname;
                return 1;
            }
            else 
            {
                cout << "\n\nNo virus detected.";
                if (ret != CL_CLEAN)
                {
                    cout << "\n\nError: " << cl_strerror(ret);
                }
                return 0;
            }
        }
        catch(const char* e)
        {
            cerr << e << endl;
        }
    }

    int destroy_engine()
    {
        cl_engine_free(engine);
        cout << "\n\nDestroyed engine.";
        return 0;
    }
};
int main()
{
    cout << "Initializing libclamav...";
    Engine new_engine;
    new_engine.init_libclamav();
    new_engine.create_engine();
    new_engine.print_datadir();
    new_engine.load_database();
    new_engine.check_database();
    new_engine.compile_engine();
    new_engine.scan_file("clam.exe");
    new_engine.destroy_engine();
    return 0;
}
