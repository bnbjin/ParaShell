template <class T>
T* pattern::singleton<T>::instance = 0;

template <class T>
pattern::singleton<T>::singleton()
{}

template <class T>
pattern::singleton<T>::singleton(const pattern::singleton<T>& ref)
{}

template <class T>
pattern::singleton<T>::~singleton()
{
	if (0 != instance)
	{
		delete instance;
	}
}

template <class T>
T* pattern::singleton<T>::getinstance()
{
	if (0 == instance)
	{
		instance = new T;
	}

	return instance;
}

template <class T>
pattern::singleton<T>& pattern::singleton<T>::operator=(pattern::singleton<T>& ref)
{
	return ref;
}
