package kerbeross;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;


public class KeyManager {

    public KeyManager() {
    }

    //  Generacion de la clave secreta usando el algoritmo AES longitud 128
    
    public SecretKey generateSecretKey() throws NoSuchAlgorithmException {

        SecretKey key;
        int KEY_SIZE = 128;
        
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        key = keyGenerator.generateKey();

        return key;
    }
}
