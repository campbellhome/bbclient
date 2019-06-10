// Copyright (c) 2012-2019 Matt Campbell
// MIT license (see License.txt)

#pragma once

#if defined(_MSC_VER) && _MSC_VER
__pragma(warning(push));
__pragma(warning(disable : 4820))
#include <malloc.h>
    __pragma(warning(pop))
#elif defined(BB_FORCE_PLATFORM_ORBIS) && BB_FORCE_PLATFORM_ORBIS
#include <stdlib.h>
#else
#include <malloc.h>
#endif
