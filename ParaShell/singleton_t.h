#ifndef __SINGLETON_H__
#define __SINGLETON_H__

namespace pattern
{

template <class T>
class singleton
{
public:

	~singleton();

	static T* getinstance();

private:

	singleton();

	singleton(const singleton<T>&);

	singleton<T>& operator=(singleton<T>&);

	static T* instance;
};

} // pattern

#include "singleton.cpp"

#endif // __SINGLETON_H__
