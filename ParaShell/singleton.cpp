#include "singleton.h"

pattern::singleton* pattern::singleton::instance = 0;

pattern::singleton::singleton()
{}

pattern::singleton::singleton(const pattern::singleton& ref)
{}

pattern::singleton::~singleton()
{}

pattern::singleton& pattern::singleton::operator=(pattern::singleton& ref)
{
	return ref;
}

pattern::singleton* pattern::singleton::getinstance()
{
	if (0 == instance)
	{
		instance = new singleton();
	}
	
	return instance;
}
