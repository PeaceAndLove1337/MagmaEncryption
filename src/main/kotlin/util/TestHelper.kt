package util

fun printStringByteArrayFromByteString(inputString: String) {
    val bytesPrefix = "(byte) 0x"
    val separator = ", "
    inputString.forEachIndexed { index, c ->
        if (index % 2 == 0)
            print(bytesPrefix)
        print(c)
        if (index % 2 != 0)
            print(separator)
    }
}
