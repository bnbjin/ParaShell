#include "config.h"


/*  状态开关  */
bool ISWORKING = false;

/*  创建备份文件开关  */
bool ISCREATEBAK = true;

/*  擦出区块共享属性开关  */
bool ISERASESHARE = false;

/*  保存额外数据开关  */
bool ISSAVEDATA = false;

/*  输入表变异开关 */
bool ISMUTATEIMPORT = true;

/*  资源压缩开关  */
bool ISPACKRES = false;

/*  重定位变异开关  */
bool ISMUTATERELOC = false;

/*  区块融合开关  */
bool ISMERGESECTION = false;