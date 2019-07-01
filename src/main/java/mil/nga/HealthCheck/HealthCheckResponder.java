package mil.nga.HealthCheck;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import mil.nga.util.FileUtils;

/**
 * Simple servlet used to test access to target web containers.  All it does
 * echo back the server name.
 * 
 * @author L. Craig Carpenter
 */
public class HealthCheckResponder extends HttpServlet {

    /**
	 * Eclipse-generated serialVersionUID
	 */
	private static final long serialVersionUID = 1143713177249611728L;

	/**
     * Default no-arg constructor. 
     */
    public HealthCheckResponder() { }

	/**
	 * Echo the server name back to the caller.
	 * 
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(
			HttpServletRequest request, 
			HttpServletResponse response) throws ServletException, IOException {
		
		try (PrintWriter out = response.getWriter()) {
			response.setContentType("text/plain");
			StringBuilder sb = new StringBuilder();
			sb.append("Server [ ");
			sb.append(FileUtils.getHostName().trim());
			sb.append(" ] is alive and serving [ ");
			sb.append(request.getContextPath());
			sb.append(" ]!");
			out.println(sb.toString());
			out.println();
			out.append("Served from [ ")
				.append(request.getContextPath())
				.append(" ]");
			out.println();
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
			HttpServletResponse response) throws ServletException, IOException {
		doGet(request, response);
	}

}
