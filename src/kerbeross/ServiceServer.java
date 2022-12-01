package kerbeross;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
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

public class ServiceServer {

    public static void main(String[] args) throws UnsupportedEncodingException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        int AUTH_PORT = 5000;
        int CLIENT_PORT = 5004;
        Scanner scanner = new Scanner(System.in);
        Comunication comunicator = new Comunication();
        Encryptor encryptor = new Encryptor();
        String ticket_V, Auth_C2V;
        String[] ticket_V_Array, Auth_C2V_Array;

        try {

            System.out.println("||  SERVICE SERVER  ||");

            //  Se conecta a la autoridad certificadora
            System.out.println(" ¬ Ingresa la IP de la autoridad certificadora: ");
            InetAddress ipAC = InetAddress.getByName(scanner.nextLine());

            //  Se recibe la Clave del Client/Servidor
            byte[] encodedSecretCV = comunicator.getBytes(16, ipAC, AUTH_PORT);
            SecretKey secretCV = new SecretKeySpec(encodedSecretCV, 0, encodedSecretCV.length, "AES");

            //  Se recibe la Clave del Servidor
            byte[] encodedSecretV = comunicator.getBytes(16, ipAC, AUTH_PORT);
            SecretKey secretV = new SecretKeySpec(encodedSecretV, 0, encodedSecretV.length, "AES");

            System.out.println("Claves recibidas y codificadas");

            //  Recibe Mensaje (5)
            System.out.println(" ¬ Ingresa la IP del Cliente: ");
            InetAddress ipC = InetAddress.getByName(scanner.nextLine());

            byte[] message_5_Bytes = comunicator.getBytes(512, ipAC, CLIENT_PORT);

            System.out.println("Mensaje (5) recibido");

            String message_5 = new String(message_5_Bytes, StandardCharsets.UTF_8).replaceAll("[\\[\\]]", "");

            //System.out.println("Mensaje (5): " +  message_5);
            String[] message_5_array = message_5.split(",");

            ticket_V = message_5_array[0].replaceAll(" ", "");

            //System.out.println("ticketv: " + ticket_V);
            byte[] ticket_V_Bytes = hexToBytes(ticket_V);

            //System.out.println("E_K_V_TICKET_V_Bytes: " + Arrays.toString(ticket_V_Bytes));
            byte[] decypher_ticket_V_Bytes = encryptor.AESDecryption(secretV, ticket_V_Bytes);

            Auth_C2V = message_5_array[1].replaceAll(" ", "");
            byte[] Auth_C2V_Bytes = hexToBytes(Auth_C2V);

            Auth_C2V_Bytes = Arrays.copyOfRange(Auth_C2V_Bytes, 0, 80);

            byte[] decypher_Auth_C2V_Bytes = encryptor.AESDecryption(secretCV, Auth_C2V_Bytes);

            //  Ticket_V
            ticket_V = new String(decypher_ticket_V_Bytes, StandardCharsets.UTF_8);
            ticket_V_Array = ticket_V.split(",");

            //  Auth_C2V
            Auth_C2V = new String(decypher_Auth_C2V_Bytes, StandardCharsets.UTF_8);
            Auth_C2V_Array = Auth_C2V.split(",");

            //  Manda Mensaje (6)
            String ts5 = Instant.now().toString();

            String[] message_6_Array = {ts5 + 1};
            String message_6 = Arrays.toString(message_6_Array);

            byte[] E_K_C_V_Message_6_Bytes = encryptor.AESEncryption(secretCV, message_6);

            //IDc
            comunicator.sendBytes(CLIENT_PORT, E_K_C_V_Message_6_Bytes);

            System.out.println("Mensaje (6) enviado");
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
