#ifndef __CONFIG_H__
#define __CONFIG_H__


#define __PARADOX_DEBUG__

/*  状态开关  */
extern bool ISWORKING;

/*  创建备份文件开关  */
extern bool ISCREATEBAK;

/*  擦出区块共享属性开关  */
extern bool ISERASESHARE;

/*  保存额外数据开关  */
extern bool ISSAVEDATA;

/*  输入表变异开关 */
extern bool ISMUTATEIMPORT;

/*  资源压缩开关  */
extern bool ISPACKRES;

/*  重定位变异开关  */
extern bool ISMUTATERELOC;

/*  区块融合开关  */
extern bool ISMERGESECTION;


#endif // __CONFIG_H__
