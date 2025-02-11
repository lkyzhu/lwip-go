package lwip

/*
#include "lwip/init.h"
#include "lwipopts.h"
*/
import "C"

import (
	_ "github.com/lkyzhu/lwip/lib"
)

func init() {
	C.lwip_init()
}
