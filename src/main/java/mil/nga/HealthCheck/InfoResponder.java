package mil.nga.HealthCheck;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;


/**
 * Servlet used to print the available request headers.  
 * 
 * @author L. Craig Carpenter
 */
public class InfoResponder extends HttpServlet {

    /**
	 * Eclipse-generated serialVersionUID
	 */
	private static final long serialVersionUID = 3822081403937362085L;

	public static final String CLIENT_CERT_HEADER = "SSL_CLIENT_CERT";
	public static final String BEGIN_CERTIFICATE = "----- BEGIN CERTIFICATE -----";
	public static final String BEGIN_CERTIFICATE2 = "-----BEGIN CERTIFICATE-----";
	public static final String END_CERTIFICATE = "----- END CERTIFICATE -----";
	public static final String END_CERTIFICATE2 = "-----END CERTIFICATE-----";
	
	/**
     * Default no-arg constructor. 
     */
    public InfoResponder() { }

    /**
     * Attempt to obtain the certificate that was used for the SSL handshake.
     * This will likely return null in most cases.
     * 
     * @param request The incoming HTTP request object.
     * @return The certificate that was used for the SSL handshake.  This will 
     * be null if the application proxies are not HTTPS.
     */
    public X509Certificate getSSLCertificate(
    		HttpServletRequest request) {
    	X509Certificate sslCert = null;
    	X509Certificate[] certs = (X509Certificate[])
    			request.getAttribute("javax.servlet.request.X509Certificate");
    	if ((certs != null) && (certs.length > 0)) {
    		sslCert = certs[0];
    	}
    	return sslCert;
    }
    
    /**
     * Attempt to obtain the client certificate from HTTP headers.
     * @param request request The incoming HTTP request object.
     * @return The client certificate forwarded by the proxy.
     */
    public X509Certificate getClientCertificate(
    		HttpServletRequest request) {
    	X509Certificate clientCert = null;
    	String certString = request.getHeader(CLIENT_CERT_HEADER);
    	if ((certString != null) && (!certString.isEmpty())) {
    		try (InputStream is = new ByteArrayInputStream(
    				Base64.decodeBase64(
    					certString
    						.replaceAll(BEGIN_CERTIFICATE, "")
    						.replaceAll(BEGIN_CERTIFICATE2, "")
    						.replaceAll(END_CERTIFICATE, "")
    						.replaceAll(END_CERTIFICATE2, "")))) {
    			CertificateFactory cFactory = 
    					CertificateFactory.getInstance("X509");
    			clientCert = (X509Certificate)cFactory.generateCertificate(is);
    		}
    		catch (Exception e) {
    			e.printStackTrace();
    		}
    	}
    	return clientCert;
    }
    
	/**
	 * Echo the request headers back to the caller.
	 * 
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	@SuppressWarnings("unchecked")
	protected void doGet(
			HttpServletRequest request, 
			HttpServletResponse response) 
					throws ServletException, IOException {

		String headerName = null;
		
		try (PrintWriter out = response.getWriter()) {
			
			response.setContentType("text/html;charset=UTF-8");
			out.println("<html>");
			out.println("<head><title>Available Request Headers</title></head>");
			out.println("<body>");
			out.println("<h1>Available Request Headers</h1>");
			
			Enumeration<String> e = request.getHeaderNames();
			if (e != null) {
				
				out.println("<table align=center border=1>");
				out.println("<tr><th> Header Name </th><th> Value </th></tr>");
				
				while (e.hasMoreElements()) {
					headerName = e.nextElement();
					if ((headerName != null) && (!headerName.isEmpty())) {
						out.println("<tr><td align=center><b>");
						out.println(headerName);
						out.println("</b><td align=center>");
						out.println(request.getHeader(headerName));
						out.println("</td></tr>");
					}
				}
				
				out.println("</table>");
				out.println("<br><br>");
			}
			else {
				out.println("<h1>Request headers not available!</h1>");
			}
			
			out.println("<h3>CGI-related Headers</h3>");
			out.print("REMOTE_HOST => [  ");
			out.print(request.getRemoteHost());
			out.println(" ].<br>");
			out.print("REMOTE_ADDR => [  ");
			out.print(request.getRemoteAddr());
			out.println(" ].<br>");
			out.print("REMOTE_USER => [  ");
			out.print(request.getRemoteUser());
			out.println(" ].<br>");
			out.print("AUTH_TYPE => [  ");
			out.print(request.getAuthType());
			out.println(" ].<br>");
			out.println("<br>");
			
			// See if we can get the user certificate.
			out.println("<h3>Client certificate information</h3>");
			X509Certificate sslCert = getSSLCertificate(request);
			X509Certificate clientCert = getClientCertificate(request);
			if (sslCert != null) {
				out.println("<h4>SSL Certificate Details</h4>");
				out.println("<pre>");
				out.print(sslCert.toString());
				out.println("</pre>");
				out.println("<br/>");
			}
			else {
				out.println("No SSL certificate available.");
			}
			if (clientCert != null) {
				out.println("<h4>Client Certificate Details</h4>");
				out.print("Available in header [ ");
				out.print(CLIENT_CERT_HEADER);
				out.println(" ].");
				out.println("<pre>");
				out.print(clientCert.toString());
				out.println("</pre>");
				out.println("<br/>");
			}
			else {
				out.println("No client certificate available.");
			}
			out.print("<h4>Served from [ ");
			out.print(request.getContextPath());
			out.println(" ].</h4><br>");
			out.println("</body></html>");
			out.flush();
		}
	}

	/**
	 * Forward POST request the GET method.
	 * 
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(
			HttpServletRequest request, 
			HttpServletResponse response) 
					throws ServletException, IOException {
		doGet(request, response);
	}

}
