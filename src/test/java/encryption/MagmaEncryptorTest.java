package encryption;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class MagmaEncryptorTest {

    @Test
    void keyExpansionTest() throws IllegalAccessException, NoSuchFieldException {
        byte[] inputEncryptionKey = new byte[]{(byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa,
                (byte) 0x99, (byte) 0x88, (byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, (byte) 0x33, (byte) 0x22,
                (byte) 0x11, (byte) 0x00,
                (byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7,
                (byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, (byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff};

        MagmaEncryptor magmaEncryptor = new MagmaEncryptor(inputEncryptionKey);

        Field field = magmaEncryptor.getClass().getDeclaredField("mExpandedKeys");
        field.setAccessible(true);

        byte[] expectedKeys = new byte[]{
                (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99, (byte) 0x88, (byte) 0x77, (byte) 0x66,
                (byte) 0x55, (byte) 0x44, (byte) 0x33, (byte) 0x22, (byte) 0x11, (byte) 0x00, (byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3,
                (byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, (byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, (byte) 0xfc, (byte) 0xfd,
                (byte) 0xfe, (byte) 0xff, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa, (byte) 0x99, (byte) 0x88,
                (byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, (byte) 0x33, (byte) 0x22, (byte) 0x11, (byte) 0x00, (byte) 0xf0, (byte) 0xf1,
                (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, (byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb,
                (byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa,
                (byte) 0x99, (byte) 0x88, (byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, (byte) 0x33, (byte) 0x22, (byte) 0x11, (byte) 0x00,
                (byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7, (byte) 0xf8, (byte) 0xf9,
                (byte) 0xfa, (byte) 0xfb,
                (byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff, (byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff,
                (byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, (byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7,
                (byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0x33, (byte) 0x22, (byte) 0x11, (byte) 0x00, (byte) 0x77, (byte) 0x66,
                (byte) 0x55, (byte) 0x44, (byte) 0xbb, (byte) 0xaa, (byte) 0x99, (byte) 0x88, (byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc
        };

        assertArrayEquals(expectedKeys, (byte[]) field.get(magmaEncryptor));
    }

    @Test
    void sBoxSubstitutionTest1() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        MagmaEncryptor magmaEncryptor = new MagmaEncryptor(new byte[]{});

        Method method = magmaEncryptor.getClass().getDeclaredMethod("sBoxSubstitution", byte[].class);
        method.setAccessible(true);

        byte[] expectedArray1 = new byte[]{(byte) 0x2a, (byte) 0x19, (byte) 0x6f, (byte) 0x34};

        byte[] actualArray1 = (byte[]) method.invoke(magmaEncryptor, (Object) new byte[]{(byte) 0xfd, (byte) 0xb9, (byte) 0x75, (byte) 0x31});
        assertArrayEquals(expectedArray1, actualArray1);
    }

    @Test
    void sBoxSubstitutionTest2() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        MagmaEncryptor magmaEncryptor = new MagmaEncryptor(new byte[]{});

        Method method = magmaEncryptor.getClass().getDeclaredMethod("sBoxSubstitution", byte[].class);
        method.setAccessible(true);

        byte[] expectedArray2 = new byte[]{(byte) 0xeb, (byte) 0xd9, (byte) 0xf0, (byte) 0x3a};

        byte[] actualArray2 = (byte[]) method.invoke(magmaEncryptor, (Object) new byte[]{(byte) 0x2a, (byte) 0x19, (byte) 0x6f, (byte) 0x34});
        assertArrayEquals(expectedArray2, actualArray2);
    }

    @Test
    void sBoxSubstitutionTest3() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        MagmaEncryptor magmaEncryptor = new MagmaEncryptor(new byte[]{});

        Method method = magmaEncryptor.getClass().getDeclaredMethod("sBoxSubstitution", byte[].class);
        method.setAccessible(true);

        byte[] expectedArray3 = new byte[]{(byte) 0xb0, (byte) 0x39, (byte) 0xbb, (byte) 0x3d};

        byte[] actualArray3 = (byte[]) method.invoke(magmaEncryptor, (Object) new byte[]{(byte) 0xeb, (byte) 0xd9, (byte) 0xf0, (byte) 0x3a});
        assertArrayEquals(expectedArray3, actualArray3);
    }

    @Test
    void sBoxSubstitutionTest4() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        MagmaEncryptor magmaEncryptor = new MagmaEncryptor(new byte[]{});

        Method method = magmaEncryptor.getClass().getDeclaredMethod("sBoxSubstitution", byte[].class);
        method.setAccessible(true);

        byte[] expectedArray4 = new byte[]{(byte) 0x68, (byte) 0x69, (byte) 0x54, (byte) 0x33};

        byte[] actualArray4 = (byte[]) method.invoke(magmaEncryptor, (Object) new byte[]{(byte) 0xb0, (byte) 0x39, (byte) 0xbb, (byte) 0x3d});
        assertArrayEquals(expectedArray4, actualArray4);
    }

    @Test
    void oneIterationEncryptTest1() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        MagmaEncryptor magmaEncryptor = new MagmaEncryptor(new byte[]{});

        Method method = magmaEncryptor.getClass().getDeclaredMethod("fTransformationFunWithXor", byte[].class,
                byte[].class, byte[].class);
        method.setAccessible(true);

        byte[] inputKey1 = new byte[]{(byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc};
        byte[] leftArray1 = new byte[]{(byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98};
        byte[] rightArray1 = new byte[]{(byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10};

        byte[] expectedResult1 = new byte[]{(byte) 0x28, (byte) 0xda, (byte) 0x3b, (byte) 0x14};

        byte[] actualResult1 = (byte[]) method.invoke(magmaEncryptor, rightArray1, inputKey1, leftArray1);
        assertArrayEquals(expectedResult1, actualResult1);
    }

    @Test
    void oneIterationEncryptTest2() throws NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        MagmaEncryptor magmaEncryptor = new MagmaEncryptor(new byte[]{});

        Method method = magmaEncryptor.getClass().getDeclaredMethod("fTransformationFunWithXor", byte[].class,
                byte[].class, byte[].class);
        method.setAccessible(true);

        byte[] inputKey2 = new byte[]{(byte) 0xbb, (byte) 0xaa, (byte) 0x99, (byte) 0x88};
        byte[] leftArray2 = new byte[]{(byte) 0x05, (byte) 0xef, (byte) 0x44, (byte) 0x01};
        byte[] rightArray2 = new byte[]{(byte) 0x23, (byte) 0x9a, (byte) 0x45, (byte) 0x77};

        byte[] expectedResult2 = new byte[]{(byte) 0xc2, (byte) 0xd8, (byte) 0xca, (byte) 0x3d};

        byte[] actualResult2 = (byte[]) method.invoke(magmaEncryptor, rightArray2, inputKey2, leftArray2);
        assertArrayEquals(expectedResult2, actualResult2);
    }

    @Test
    void oneBlockEncodeTest() {
        byte[] inputEncryptionKey = new byte[]{(byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa,
                (byte) 0x99, (byte) 0x88, (byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, (byte) 0x33, (byte) 0x22,
                (byte) 0x11, (byte) 0x00,
                (byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7,
                (byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, (byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff};
        byte[] inputBytes = new byte[]{(byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98,
                (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10};
        byte[] expectedBytes = new byte[]{
                (byte) 0x4E, (byte) 0xE9, (byte) 0x01, (byte) 0xE5, (byte) 0xC2, (byte) 0xD8, (byte) 0xCA, (byte) 0x3D
        };


        MagmaEncryptor me = new MagmaEncryptor(inputEncryptionKey);

        byte[] actualBytes = me.oneBlockEncode(inputBytes);

        assertArrayEquals(expectedBytes, actualBytes);

    }

    @Test
    void oneBlockDecodeTest(){
        byte[] inputEncryptionKey = new byte[]{(byte) 0xff, (byte) 0xee, (byte) 0xdd, (byte) 0xcc, (byte) 0xbb, (byte) 0xaa,
                (byte) 0x99, (byte) 0x88, (byte) 0x77, (byte) 0x66, (byte) 0x55, (byte) 0x44, (byte) 0x33, (byte) 0x22,
                (byte) 0x11, (byte) 0x00,
                (byte) 0xf0, (byte) 0xf1, (byte) 0xf2, (byte) 0xf3, (byte) 0xf4, (byte) 0xf5, (byte) 0xf6, (byte) 0xf7,
                (byte) 0xf8, (byte) 0xf9, (byte) 0xfa, (byte) 0xfb, (byte) 0xfc, (byte) 0xfd, (byte) 0xfe, (byte) 0xff};
        byte[] inputBytes = new byte[]{(byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98,
                (byte) 0x76, (byte) 0x54, (byte) 0x32, (byte) 0x10};

        MagmaEncryptor me = new MagmaEncryptor(inputEncryptionKey);

        byte[] encodedBytes = me.oneBlockEncode(inputBytes);
        byte[] actualBytes = me.oneBlockDecode(encodedBytes);


        assertArrayEquals(inputBytes, actualBytes);
    }
}