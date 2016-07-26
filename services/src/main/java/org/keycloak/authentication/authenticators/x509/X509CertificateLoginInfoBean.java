package org.keycloak.authentication.authenticators.x509;

/**
 * @author <a href="mailto:petervn1@yahoo.com">Peter Nalyvayko</a>
 * @version $Revision: 1 $
 * @date 7/26/2016
 */

public final class X509CertificateLoginInfoBean {

    private boolean _isCertificateValid = false;
    private boolean _isUserValid = false;
    private boolean _isUserEnabled = false;
    public X509CertificateLoginInfoBean() {
    }

    public void setIsCertificateValid(boolean value) { _isCertificateValid = value; }
    public boolean getIsCertificateValid() { return _isCertificateValid; }
    public void setIsUserValid(boolean value) { _isUserValid = value; }
    public boolean getIsUserValid() { return _isUserValid; }
    public void setIsUserEnabled(boolean value) { _isUserEnabled = value; }
    public boolean getIsUserEnabled() { return _isUserEnabled; }
}
