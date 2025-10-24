/*
    XtH

    :copyright: (c) 2025 by OCH authors.
    :license: Creative Commons CC0 1.0
*/

#include <assert.h>

#include <cryptography-run/aead.h>
#include <cryptography-run/hash.h>
#include <cryptography-run/perm.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../../internal.h"
#include "../../../perm/areion/areion.h"
#include "cryptography-run/axu.h"
#include "cryptography-run/gf256.h"