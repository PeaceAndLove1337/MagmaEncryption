import encryption.MagmaEncryptor
import encryption.MagmaParallelEncryptor
import encryption.PasswordToKeyConverter
import java.nio.file.Files
import java.nio.file.Paths

fun main() {
    val fileExamplesPathString = "fileExamples/"
    val password = "HellO_WorlD12!#"
    val countOfThreads = 1
    val countOfTasksPerThread = 20

    /*computeWithTime("Encoding file1 time:") {
        encodeFileByPass(
            fileExamplesPathString.plus("file1jpg/file1.jpg"),
            password,
            true
        )
    }*/
    computeWithTime("Encoding file1 parallel"){
        parallelEncodeFileByPass(
            fileExamplesPathString.plus("file1jpg/file1.jpg"),
            password,
            15,
            20,
            true
        )
    }

}


fun getFileInputBytes(filePath: String): ByteArray =
    Files.readAllBytes(Paths.get(filePath))

fun writeBytesToFile(filePath: String, byteArray: ByteArray) {
    Files.write(Paths.get(filePath), byteArray)
}

fun getKeyByStringPassword(password: String): ByteArray =
    PasswordToKeyConverter(password).bytesFromPassBySha

fun <T> computeWithTime(timeMessage: String, codeBlock: () -> T): T {
    val timeBefore = System.currentTimeMillis()
    val result = codeBlock.invoke()
    val timeAfter = System.currentTimeMillis()
    println("$timeMessage : ${(timeAfter - timeBefore).toDouble() / 1000}")
    return result
}

fun encodeFileByPass(filePath: String, password: String, saveEncodedFile: Boolean): ByteArray {
    val key = getKeyByStringPassword(password)
    val inputBytes = getFileInputBytes(filePath)
    val encryptor = MagmaEncryptor(key)
    val res = encryptor.encryptInCodeBook(inputBytes)
    if (saveEncodedFile) {
        writeBytesToFile("${filePath}_encoded", res)
    }
    return res
}

fun decodeFileByPass(filePath: String, password: String, saveDecodedFile: Boolean): ByteArray {
    val key = getKeyByStringPassword(password)
    val inputBytes = getFileInputBytes("${filePath}_encoded")
    val encryptor = MagmaEncryptor(key)
    val res = encryptor.decryptInCodeBook(inputBytes)
    if (saveDecodedFile) {
        writeBytesToFile("${filePath}_decoded", res)
    }
    return res
}

fun parallelEncodeFileByPass(
    filePath: String,
    password: String,
    countOfThreads: Int,
    countOfTasksPerThread: Int,
    saveEncodedFile: Boolean
): ByteArray {
    val key = getKeyByStringPassword(password)
    val inputBytes = getFileInputBytes(filePath)
    val encryptor = MagmaParallelEncryptor(key, countOfThreads, countOfTasksPerThread)
    val res = encryptor.encryptInCodeBook(inputBytes)
    if (saveEncodedFile) {
        writeBytesToFile("${filePath}_parallel_encoded", res)
    }
    return res
}

fun parallelDecodeFileByPass(
    filePath: String,
    password: String,
    countOfThreads: Int,
    countOfTasksPerThread: Int,
    saveEncodedFile: Boolean
): ByteArray {
    val key = getKeyByStringPassword(password)
    val inputBytes = getFileInputBytes("${filePath}_parallel_encoded")
    val encryptor = MagmaParallelEncryptor(key, countOfThreads, countOfTasksPerThread)
    val res = encryptor.decryptInCodeBook(inputBytes)
    if (saveEncodedFile) {
        writeBytesToFile("${filePath}_parallel_decoded", res)
    }
    return res
}