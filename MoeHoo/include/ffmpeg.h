// 该部分用于替换FFMPEG依赖目标
#include <windows.h>
class ffmpeg
{
private:
public:
    static ffmpeg *GetInstance(const char* Libary)
    {
        //dlopen();
        //LoadLibrary();
        return (ffmpeg *)nullptr;
    }
    bool InitFFmpeg()
    {
    }
    void *Audio2Wav()
    {
        return nullptr;
    }
    void *VideoGetInfo()
    {
        return nullptr;
    }
};
