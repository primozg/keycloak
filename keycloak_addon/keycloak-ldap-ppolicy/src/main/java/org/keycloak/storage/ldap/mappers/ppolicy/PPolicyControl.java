/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.keycloak.storage.ldap.mappers.ppolicy;

/**
 *
 * @author Uporabnik
 */
import javax.naming.ldap.Control;
public class PPolicyControl implements Control{
    protected static final String value="1.3.6.1.4.1.42.2.27.8.5.1";
    public PPolicyControl(){
    
    }
    
	public byte[] getEncodedValue() {
		return null;
	}
        
        public String getControlName(){
        return "PPolicyControl";
        }
	public String getID() {
		//return "1.3.18.0.2.10.15";
                return value;        

	}

	public String getOID() {
                return value;       

	}
 
	public String getValue() {
                return null;    
	}        
	public boolean isCritical() {
		return false;
	}
	public Control[] getControls() {
		return new Control[]{this};
	}
}