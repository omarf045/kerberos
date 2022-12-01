package kerbeross;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
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

public class TGS {

    public static void main(String[] args) throws IllegalBlockSizeException, UnknownHostException, IOException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        int AUTH_PORT = 5000, C_TGS_PORT = 5002;
        Scanner scanner = new Scanner(System.in);
        Comunication comunicator = new Comunication();
        Encryptor cryptor = new Encryptor();

        System.out.println("||  TICKET GRANTING SERVER  ||");
        
        //  Se conecta a la autoridad certificadora
        System.out.println(" ¬ Ingresa la IP de la autoridad certificadora: ");
        InetAddress ipAuth = InetAddress.getByName(scanner.nextLine());

        //  Se recibe la Clave del TGS
        byte[] encodedSecretTGS = comunicator.getBytes(16, ipAuth, AUTH_PORT);
        SecretKey secretTGS = new SecretKeySpec(encodedSecretTGS, 0, encodedSecretTGS.length, "AES");
        //System.out.println(encodedSecretTGS.length);

        //  Se recibe la Clave del Client/TGS
        byte[] encodedSecretCTGS = comunicator.getBytes(16, ipAuth, AUTH_PORT);
        SecretKey secretCTGS = new SecretKeySpec(encodedSecretCTGS, 0, encodedSecretCTGS.length, "AES");

        //  Se recibe la Clave del Servidor
        byte[] encodedSecretV = comunicator.getBytes(16, ipAuth, AUTH_PORT);
        SecretKey secretV = new SecretKeySpec(encodedSecretV, 0, encodedSecretV.length, "AES");

        //System.out.println("SecretV: " + Base64.getEncoder().encodeToString(secretV.getEncoded()));
        
        //  Se recibe la Clave del Client/Servidor
        byte[] encodedSecretCV = comunicator.getBytes(16, ipAuth, AUTH_PORT);
        SecretKey secretCV = new SecretKeySpec(encodedSecretCV, 0, encodedSecretCV.length, "AES");

        System.out.println("Claves recibidas y codificadas");

        ///////////////////////////////////////////////////////////////////////////////////////////////////
        //  Se conecta al Client
        System.out.println(" ¬ Ingresa la IP del cliente: ");
        InetAddress ipC = InetAddress.getByName(scanner.nextLine());

        // Recibe Message 3
        byte[] message_3_Bytes = comunicator.getBytes(512, ipC, C_TGS_PORT);
        String message_3 = new String(message_3_Bytes, StandardCharsets.UTF_8).replaceAll("[\\[\\]]", "");
        System.out.println("Mensaje (3) recibido");
        
        //System.out.println("Message 3: " + message_3);

        String[] message_3_Array = message_3.split(",");

        String ID_V, E_K_TGS_Ticket_TGS, AUTH_C;

        ID_V = message_3_Array[0];
        //System.out.println(ID_V);
        //System.out.println(ID_V.length());

        E_K_TGS_Ticket_TGS = message_3_Array[1];

        AUTH_C = message_3_Array[2];

        byte[] E_K_TGS_Ticket_TGS_Bytes = hexToBytes(E_K_TGS_Ticket_TGS);
        
        E_K_TGS_Ticket_TGS_Bytes = Arrays.copyOfRange(E_K_TGS_Ticket_TGS_Bytes, 1, E_K_TGS_Ticket_TGS_Bytes.length);

        //System.out.println("E_K_TGS_Ticket_TGS: " + E_K_TGS_Ticket_TGS);
        //System.out.println("E_K_TGS_Ticket_TGS_Bytes: " + E_K_TGS_Ticket_TGS_Bytes);
        //System.out.println("E_K_TGS_Ticket_TGS_Bytes.length: " + E_K_TGS_Ticket_TGS_Bytes.length);
 
        //System.out.println(E_K_TGS_Ticket_TGS_Bytes.length);
        byte[] Ticket_TGS_Bytes = cryptor.AESDecryption(secretTGS, E_K_TGS_Ticket_TGS_Bytes);

        String Ticket_TGS = new String(Ticket_TGS_Bytes, StandardCharsets.UTF_8);
            
        //System.out.println(Ticket_TGS);
        
        Ticket_TGS = Ticket_TGS.replace("[", "").replace("]", "");

        String[] ticket_TGS_Array = Ticket_TGS.split(",");

        String ID_C, AD_C, TS_4, LT_4;

        ID_C = ticket_TGS_Array[1];
        AD_C = ticket_TGS_Array[2];

        TS_4 = Instant.now().toString();
        LT_4 = "5";

        String K_C_V = bytesToHex(encodedSecretCV);

        // Se crea E_K_V_TICKET_V
        String[] ticket_V_Array = {K_C_V, ID_C, AD_C, ID_V, TS_4, LT_4};
        String ticket_V = Arrays.toString(ticket_V_Array);
        
        byte[] E_K_V_Ticket_V_Bytes = cryptor.AESEncryption(secretV, ticket_V);
        //String E_K_V_Ticket_V = new String(E_K_V_Ticket_V_Bytes, StandardCharsets.UTF_8);
        String E_K_V_Ticket_V = bytesToHex(E_K_V_Ticket_V_Bytes);
        //System.out.println("E_K_V_TICKET_V: " + E_K_V_Ticket_V);
        //System.out.println("E_K_V_TICKET_V_Bytes: " + Arrays.toString(E_K_V_Ticket_V_Bytes));

        // Se crea (4)
        String[] message_4_Array = {K_C_V, ID_V, TS_4, E_K_V_Ticket_V};
        String message_4 = Arrays.toString(message_4_Array);
        byte[] E_K_C_TGS_message_4_Bytes = cryptor.AESEncryption(secretCTGS, message_4);

        //System.out.println("E_K_C_TGS_message_4_Bytes: " + Arrays.toString(E_K_C_TGS_message_4_Bytes));
        //("E_K_C_TGS_message_4_Bytes.length: "+ E_K_C_TGS_message_4_Bytes.length);
        comunicator.sendBytes(C_TGS_PORT, E_K_C_TGS_message_4_Bytes);
        System.out.println("Mensaje (4) enviado");
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
