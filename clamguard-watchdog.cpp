#include <iostream>
#include <string>
#include <thread>
#include "include\clamav.h"
using namespace std;


class Engine
{
public:

    struct cl_engine* engine;
    unsigned int sigs = 0;
    int ret;
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
        cout << "\n\nLoading database...";
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

    int compile_engine()
    {
        if ((ret = cl_engine_compile(engine)) != CL_SUCCESS)
        {
            cout << "Error at cl_engine_compile() : " << cl_strerror(ret);
            cl_engine_free(engine);
            return 1;
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
    cout << "\nInitializing libclamav...";
    Engine new_engine;
    new_engine.init_libclamav();
    new_engine.create_engine();
    new_engine.print_datadir();
    new_engine.load_database();
    new_engine.destroy_engine();
    return 0;
}
