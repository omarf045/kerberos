package kerbeross;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AS {

    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        int AUTH_PORT = 5000, AS_C_PORT = 5003;
        Scanner scanner = new Scanner(System.in);
        Comunication comunicator = new Comunication();
        Encryptor cryptor = new Encryptor();

        try {
            System.out.println("||  AUTHENTICATION SERVER  ||");

            //  Se conecta a la autoridad certificadora
            System.out.println(" ¬ Ingresa la IP de la autoridad certificadora: ");
            InetAddress ipAS = InetAddress.getByName(scanner.nextLine());

            //  Se recibe la Clave del Client
            byte[] encodedSecretC = comunicator.getBytes(16, ipAS, AUTH_PORT);
            SecretKey secretC = new SecretKeySpec(encodedSecretC, 0, encodedSecretC.length, "AES");
            //System.out.println("Llave Secreta Client: " + secretC.toString());

            //  Se recibe la Clave del Client/TGS
            byte[] encodedSecretCTGS = comunicator.getBytes(16, ipAS, AUTH_PORT);
            SecretKey secretCTGS = new SecretKeySpec(encodedSecretCTGS, 0, encodedSecretCTGS.length, "AES");
            //System.out.println("Llave Secreta Client/TGS: " + secretCTGS);
            //  Se recibe la Clave del TGS
            byte[] encodedSecretTGS = comunicator.getBytes(16, ipAS, AUTH_PORT);
            SecretKey secretTGS = new SecretKeySpec(encodedSecretTGS, 0, encodedSecretTGS.length, "AES");

            System.out.println("Claves recibidas y codificadas");

            //  Se conecta al Client
            System.out.println(" ¬ Ingresa la IP del cliente: ");
            InetAddress ipC = InetAddress.getByName(scanner.nextLine());

            //  Obtiene el ID del TGS
            System.out.println(" ¬ Ingresa la IP del TGS: ");
            InetAddress ipTGS = InetAddress.getByName(scanner.nextLine());
            String Str_ipTGS = ipTGS.toString();
            byte[] TGSBytesC = Str_ipTGS.getBytes();

            //  Recibe (1)
            byte[] message_1_Bytes = comunicator.getBytes(512, ipC, AS_C_PORT);
            String message_1 = new String(message_1_Bytes, StandardCharsets.UTF_8).replaceAll("[\\[\\]]", "");;
            String[] message_1_Array = message_1.split(",");
            System.out.println("Mensaje (1) recibido");

            String ID_C, ID_TGS, TS_1;

            ID_C = message_1_Array[0];
            ID_TGS = message_1_Array[1];
            TS_1 = message_1_Array[2];

            String TS_2, LT_2, AD_C, K_C_TGS;

            TS_2 = Instant.now().toString();
            LT_2 = "5";
            AD_C = ipC.getHostAddress();
            //K_C_TGS = new String(secretCTGS.getEncoded(), StandardCharsets.UTF_8);
            K_C_TGS = bytesToHex(secretCTGS.getEncoded());

            // Se crea E_K_TGS_TICKET_TGS
            String[] ticket_TGS_Array = {K_C_TGS, ID_C, AD_C, ID_TGS, TS_2, LT_2};
            String ticket_TGS = Arrays.toString(ticket_TGS_Array);
            byte[] E_K_TGS_Ticket_TGS_Bytes = cryptor.AESEncryption(secretTGS, ticket_TGS);
            String E_K_TGS_Ticket_TGS = bytesToHex(E_K_TGS_Ticket_TGS_Bytes);

            //System.out.println("K_C_TGS_Bytes.length: " + secretCTGS.getEncoded().length);
            //System.out.println("K_C_TGS_Bytes: " + secretCTGS.getEncoded());
            //System.out.println("K_C_TGS: " + K_C_TGS);
            // Se crea (2)
            String[] message_2_Array = {K_C_TGS, ID_TGS, TS_2, LT_2, E_K_TGS_Ticket_TGS};
            String message_2 = Arrays.toString(message_2_Array);

            byte[] E_K_C_message_2_Bytes = cryptor.AESEncryption(secretC, message_2);
            //System.out.println(E_K_C_message_2_Bytes.length);

            System.out.println("Esperando al Cliente...");
            comunicator.sendBytes(AS_C_PORT, E_K_C_message_2_Bytes);
            System.out.println("Mensaje (2) enviado");

            //  TicketTGS          
        } catch (IOException ex) {
            System.out.println(ex);
        }

    }

    // Convertir de String (hexadecimal) a bytes
    public static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    // Convertir de bytes a String (hexadecimal)
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }

}
