/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package yo.co.ug.yopaymentssdk;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author josephtabajjwa
 */
public class VerifySignature {
    
    static String PUBLIC_KEY_PATH = "/Users/josephtabajjwa/Desktop/Joe/projects/yopayments API/Java/yopaymentssdk/target/keys/Yo_Uganda_Public_Certificate.crt";
    
    public static void main(String[] args) {
        
        String datetime = "2014-02-07 14:48:07";
        String amount = "1000";
        String narrative = "SpinApp Userid:7 Number:256783086794";
        String network_ref = "1327659406";
        String external_ref = "";
        String msisdn = "256783086794";
        String signatureBase64 = "05b4cTk+IDhI8aqRhsFR2zXbbl9xfWJPHO+WAn/sSWCCB0zQeePvqjUTONk6w8wcaue0YbCO2cd1ER3l0K8aJUj8Ob7Ixl7o5cNsYwCHu8cDenBFxUL8UBnlSxZAkOXf/vi47rwT3Eon9KpPJxJISLnp1vyVJgkWAH9GFsX1zLY33314sekJ1KFzPxY55vkTaUic9BfpIKsj+L4XFcgHpnJHqA20byAEE8uYmdrrSbwlCnEdqJx3ROE3gxMS/M0gAwPcjZFziawAfFaUARogFmrkRA9KKjA9XLPMvN8tN8vNwVbg8xV5p/K4pmBA3Z4DtnJAaYAeUXvgW8Dij+UDdw==";
        
        String signedData = datetime+amount+narrative+network_ref+external_ref
                +msisdn;
        
        //First read the public key from the file
        String pKeyString = YoPaymentsUtils.readAllBytesFromFile(PUBLIC_KEY_PATH);
        if (pKeyString == null) {
            Logger.getLogger(VerifySignature.class.getName())
                    .log(Level.SEVERE, "Couldn't read PK from file", "");
            return;
        }
        
        try {
            Signature sign = Signature.getInstance("SHA1withRSA");
            
            //Obtain the public key resource
            PublicKey publicKey = YoPaymentsUtils.getPublicKeyFromBase64String(pKeyString);
            //PublicKey publicKey = YoPaymentsUtils.getKey(PUBLIC_KEY_PATH);
            if (publicKey==null) {
                System.out.print("PublicKey must not be null");
                return;
            }
            
            sign.initVerify(publicKey);
            sign.update(signedData.getBytes());
            
            //Try to decode base64 to byte array
            byte[] signature_content;
            try{
                signature_content = Base64.getDecoder().decode(signatureBase64);
            } catch (Exception e) {
                Logger.getLogger(VerifySignature.class.getName())
                        .log(Level.SEVERE, e.getMessage(), "");
                return;
            }

            //Now check the signature
            if (signature_content.length < 256) {
                System.out.print("Invalid Base64 signature data");
                return;
            }

            if (!sign.verify(signature_content)) {
                System.out.print("Signature verification FAILED");
                return;
            }
            
            
            System.out.print("Signature verification PASSED");
            

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(VerifySignature.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return;
        } catch (InvalidKeyException ex) {
            Logger.getLogger(VerifySignature.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return;
        } catch (SignatureException ex) {
            Logger.getLogger(VerifySignature.class.getName()).log(Level.SEVERE, ex.getMessage(), ex);
            return;
        }
        
    }
    
}
