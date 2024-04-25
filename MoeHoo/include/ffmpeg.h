// 该部分用于替换FFMPEG依赖目标
class ffmpeg
{
private:
public:
    static ffmpeg *GetInstance()
    {
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
