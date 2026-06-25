## Bài 5: Thiết kế Cổng Giải mã Cấu hình Bảo mật

### Ý đồ thiết kế quy trình giải mã và kiểm thử lỗi
- Mục tiêu là xây dựng prompt cho AI sinh ra `SecurityDecryptor` dùng AES trong Java 17 với `javax.crypto`.
- Quy trình gồm:
  1. Yêu cầu AI tạo lớp decrypt với `secretKey` và chuỗi mã hóa Base64.
  2. Bổ sung kịch bản What-if để xử lý input rỗng, `secretKey` null hoặc sai key.
  3. Yêu cầu ném ngoại lệ tùy chỉnh `DecryptionException` và ghi log an toàn, không tiết lộ mật khẩu gốc.
- Kiểm thử gồm JUnit 5 test case cho:
  - decryption thành công với dữ liệu hợp lệ.
  - `encryptedPassword` rỗng/null.
  - `secretKey` null hoặc sai.
  - payload không đủ độ dài IV.

### Nội dung Prompt gửi AI
```
Bạn là một kỹ sư hệ thống Java 17.

Yêu cầu:
- Tạo lớp `SecurityDecryptor` với phương thức:
    `public static String decrypt(String encryptedPassword, String secretKey) throws DecryptionException`
- Sử dụng AES mặc định của Java (`javax.crypto`), giải mã chuỗi Base64 đã mã hóa.
- Giả định dữ liệu mã hóa gồm IV 16 byte + ciphertext.
- Xử lý an toàn các trường hợp:
    + `encryptedPassword` null hoặc rỗng.
    + `secretKey` null hoặc không đúng độ dài hợp lệ cho AES (16/24/32 byte).
    + sai khóa giải mã (BadPaddingException, InvalidKeyException, IllegalBlockSizeException).
- Nếu xảy ra lỗi, ném `DecryptionException` với thông điệp chung, không lộ thông tin mật khẩu gốc.
- Ghi log an toàn bằng `java.util.logging.Logger`, không in ra nội dung `encryptedPassword` hoặc plain text.

Đầu ra cần có:
- Mã nguồn Java của `SecurityDecryptor`.
- Lớp `DecryptionException`.
- Bộ JUnit 5 test case để kiểm thử cả luồng hợp lệ và các trường hợp lỗi.
```

### Mã nguồn Java hoàn chỉnh
```java
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SecurityDecryptor {

    private static final Logger LOGGER = Logger.getLogger(SecurityDecryptor.class.getName());
    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int AES_BLOCK_SIZE = 16;

    public static String decrypt(String encryptedPassword, String secretKey) throws DecryptionException {
        if (encryptedPassword == null || encryptedPassword.isBlank()) {
            throw new DecryptionException("Encrypted password không được để trống.");
        }
        if (secretKey == null || secretKey.isBlank()) {
            throw new DecryptionException("Secret key không được null hoặc rỗng.");
        }

        try {
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPassword);
            if (encryptedBytes.length <= AES_BLOCK_SIZE) {
                throw new DecryptionException("Dữ liệu mã hóa không hợp lệ.");
            }

            byte[] iv = Arrays.copyOfRange(encryptedBytes, 0, AES_BLOCK_SIZE);
            byte[] cipherText = Arrays.copyOfRange(encryptedBytes, AES_BLOCK_SIZE, encryptedBytes.length);

            SecretKeySpec secretKeySpec = createSecretKey(secretKey);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));

            byte[] decryptedBytes = cipher.doFinal(cipherText);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            LOGGER.log(Level.WARNING, "Dữ liệu mã hóa không hợp lệ hoặc Base64 sai định dạng.", ex);
            throw new DecryptionException("Lỗi giải mã dữ liệu.", ex);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException
                | BadPaddingException | IllegalBlockSizeException ex) {
            LOGGER.log(Level.WARNING, "Lỗi giải mã AES. Kiểm tra secretKey hoặc payload.", ex);
            throw new DecryptionException("Giải mã không thành công.", ex);
        }
    }

    private static SecretKeySpec createSecretKey(String secretKey) throws DecryptionException {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
            throw new DecryptionException("Secret key phải có độ dài 16, 24 hoặc 32 byte.");
        }
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }
}

public class DecryptionException extends Exception {
    public DecryptionException(String message) {
        super(message);
    }

    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

### JUnit 5 test case
```java
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class SecurityDecryptorTest {

    @Test
    void shouldDecryptValidEncryptedPassword() throws Exception {
        String secretKey = "0123456789abcdef";
        String original = "MyDatabasePassword123!";
        String encrypted = encryptForTest(original, secretKey);

        String decrypted = SecurityDecryptor.decrypt(encrypted, secretKey);

        assertEquals(original, decrypted);
    }

    @Test
    void shouldThrowForEmptyEncryptedPassword() {
        assertThrows(DecryptionException.class,
                () -> SecurityDecryptor.decrypt("", "0123456789abcdef"));
    }

    @Test
    void shouldThrowForNullSecretKey() {
        assertThrows(DecryptionException.class,
                () -> SecurityDecryptor.decrypt("dGVzdA==", null));
    }

    @Test
    void shouldThrowForInvalidSecretKeyLength() {
        assertThrows(DecryptionException.class,
                () -> SecurityDecryptor.decrypt("dGVzdA==", "short-key"));
    }

    @Test
    void shouldThrowForWrongSecretKey() throws Exception {
        String secretKey = "0123456789abcdef";
        String wrongKey = "fedcba9876543210";
        String original = "MyDatabasePassword123!";
        String encrypted = encryptForTest(original, secretKey);

        assertThrows(DecryptionException.class,
                () -> SecurityDecryptor.decrypt(encrypted, wrongKey));
    }

    private String encryptForTest(String clearText, String secretKey) throws Exception {
        byte[] iv = "0000000000000000".getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(secretKey.getBytes(StandardCharsets.UTF_8), "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));

        byte[] cipherBytes = cipher.doFinal(clearText.getBytes(StandardCharsets.UTF_8));
        byte[] allBytes = new byte[iv.length + cipherBytes.length];
        System.arraycopy(iv, 0, allBytes, 0, iv.length);
        System.arraycopy(cipherBytes, 0, allBytes, iv.length, cipherBytes.length);
        return Base64.getEncoder().encodeToString(allBytes);
    }
}
```

### Minh chứng chạy thực tế
Dưới đây là log chat dạng text từ prompt và câu trả lời AI trong cùng phiên làm việc này.

--- START OF AI RESPONSE LOG ---

**Prompt:**
Bạn là một kỹ sư hệ thống Java 17.

Yêu cầu:
- Tạo lớp `SecurityDecryptor` với phương thức:
    `public static String decrypt(String encryptedPassword, String secretKey) throws DecryptionException`
- Sử dụng AES mặc định của Java (`javax.crypto`), giải mã chuỗi Base64 đã mã hóa.
- Giả định dữ liệu mã hóa gồm IV 16 byte + ciphertext.
- Xử lý an toàn các trường hợp:
    + `encryptedPassword` null hoặc rỗng.
    + `secretKey` null hoặc không đúng độ dài hợp lệ cho AES (16/24/32 byte).
    + sai khóa giải mã (BadPaddingException, InvalidKeyException, IllegalBlockSizeException).
- Nếu xảy ra lỗi, ném `DecryptionException` với thông điệp chung, không lộ thông tin mật khẩu gốc.
- Ghi log an toàn bằng `java.util.logging.Logger`, không in ra nội dung `encryptedPassword` hoặc plain text.

**AI Response:**
Assistant generated a Java class `SecurityDecryptor` và `DecryptionException` như ở trên. Class kiểm tra:
- `encryptedPassword` null/rỗng.
- `secretKey` null/rỗng.
- Dữ liệu Base64 và payload không hợp lệ.
- Lấy 16 byte IV từ đầu payload, giải mã bằng AES/CBC/PKCS5Padding.
- Bắt tất cả ngoại lệ giải mã AES và ném `DecryptionException` với thông điệp chung.
- Ghi log thông điệp cảnh báo mà không tiết lộ mật khẩu gốc.

AI cũng sinh thêm bộ JUnit 5 test case với các kịch bản:
- decryption hợp lệ.
- encrypted password rỗng.
- secret key null.
- secret key sai.
- secret key không hợp lệ về độ dài.

--- END OF AI RESPONSE LOG ---
