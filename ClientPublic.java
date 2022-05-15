/* ------------------
 ClientPublic
 usage: java ClientPublic [Server hostname] [Server RTSP listening port] [Video file requested]
 ---------------------- */

import java.io.*;
import java.nio.*;
import java.net.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.Timer;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyAgreement;
//add
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketException;
import java.util.StringTokenizer;


import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import javax.crypto.interfaces.DHPublicKey;

import java.security.spec.InvalidParameterSpecException;

import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;

import java.util.Base64;

import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.nio.channels.DatagramChannel;
// import java.util.Timer;
import java.net.InetSocketAddress;

import java.lang.Throwable;

public class ClientPublic {

    int RTSPSeqNb = 0; //Sequence number of RTSP messages within the session

	private DatagramSocket send_socket;
    //private BufferedWriter out;
    //private BufferedReader in1;
    //private Socket socket;
    private Socket socket1;
    //private BufferedReader in;
    //private ServerSocket listner;
    private ServerSocket listner1;
    private InetAddress Address;
    private InetAddress Address1;

	//RTP variables:
    //----------------

    private  DatagramPacket rcvdp,senddp,rcvdp_info,packet_loss; //UDP packet received from the server
    DatagramSocket RTPsocket,RTPsocket_time; //socket to be used to send and receive UDP packets
    DatagramSocket RTPsocket_info; //socket to be used to send and receive UDP packets
    final static int RTP_RCV_PORT = 25000; //port where the client will receive the RTP packets
    final static int RTP_RCV_PORT_INFO = 20000; //port where the client will receive the RTP packets
    private DatagramChannel channel;
    int messagenb=0;
    Timer timer; //timer used to receive data from the UDP socket
    private byte[] buf; //buffer used to store data received from the server
    private byte[] buf1; //buffer used to store data received from the server
    static int Message_LENGTH = 500;
    //RTSP variables
    //----------------
    //rtsp states
    private static int EN_STATE;
    private static int CLEAR = 0;
    private static int DHON = 1;
    private static int RSAON = 2;
    private static int INIT = 0;
    private static int READY = 1;
    private static int DHREADY = 8;
    private static int CHATTING = 2;
	private static int PLAYING = 2;
    private static int STOP = 3;
    private static int state; //RTSP state == INIT or READY or PLAYING
    private Socket RTSPsocket; //socket used to send/receive RTSP messages
    private ServerSocket ss;
    private Socket s;

    private Socket socket;

	//input and output stream filters
    private static BufferedReader RTSPBufferedReader;
    private static BufferedWriter RTSPBufferedWriter;
    private static String VideoFileName; //video file to request to the server
    //Sequence number of RTSP messages within the session
    final static int SETUP = 3;
    final static int PLAY = 4;
    final static int PAUSE = 5;
    final static int TEARDOWN = 6;

    private  String ServerHost;
	private static InetAddress ServerIPAddr;
    private int RTSP_server_port,reply_code;
    private Thread  timerplayThread;
    private int RTSPid = 999; //ID of the RTSP session (given by the RTSP Server)


    private String CRLF = "\r\n";
    private String dh_shared_secret;

	//Encryption
	private static String encryptionKey = "AESEncryption123";

	// GUI
	// ----
	JFrame f = new JFrame("ClientPublic");

	JButton setupButton = new JButton("Setup");

	JButton playButton = new JButton("Play");

	JButton pauseButton = new JButton("Pause");

	JButton tearButton = new JButton("Teardown");

	JPanel mainPanel = new JPanel();

	JPanel buttonPanel = new JPanel();

	JLabel iconLabel = new JLabel();

	ImageIcon icon;

	// Video constants:
	// ------------------
	static int MJPEG_TYPE = 26; // RTP payload type for MJPEG video

	int imagenb = 1;
	static int show_hash_until = -1;
	int LossData;

	// --------------------------
	// Constructor
	// --------------------------
	public ClientPublic() {

		// build GUI
		// --------------------------

		// Frame
		f.addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				System.exit(0);
			}
		});

		// Buttons
		buttonPanel.setLayout(new GridLayout(1, 0));
		buttonPanel.add(setupButton);
		buttonPanel.add(playButton);
		buttonPanel.add(pauseButton);
		buttonPanel.add(tearButton);
		setupButton.addActionListener(new setupButtonListener());
		playButton.addActionListener(new playButtonListener());
		pauseButton.addActionListener(new pauseButtonListener());
		tearButton.addActionListener(new tearButtonListener());

		// Image display label
		iconLabel.setIcon(null);

		// frame layout
		mainPanel.setLayout(null);
		mainPanel.add(iconLabel);
		mainPanel.add(buttonPanel);
		iconLabel.setBounds(0, 0, 380, 280);
		buttonPanel.setBounds(0, 280, 380, 50);

		f.getContentPane().add(mainPanel, BorderLayout.CENTER);
		f.setSize(new Dimension(390, 370));
		f.setVisible(true);

		// init timer
		// --------------------------
		timer = new Timer(20, new timerListener());
		timer.setInitialDelay(0);
		timer.setCoalesce(true);

		// allocate enough memory for the buffer used to receive data from the
		// server
		buf = new byte[15008];
		buf1 = new byte[8];
	}

	// ------------------------------------
	// main
	// ------------------------------------
	public static void main(String argv[]) throws Exception {
		// Create a Client object
		ClientPublic theClient = new ClientPublic();

		// get server RTSP port and IP address from the command line
		// ------------------
		String ServerHost = argv[0];
		int RTSP_server_port = Integer.parseInt(argv[1]);
		ServerIPAddr = InetAddress.getByName(ServerHost);

		if (argv.length >= 3) 
			encryptionKey = String.valueOf(argv[2]);
		
		if (argv.length >= 4) 
			show_hash_until = Integer.parseInt(argv[3]);

		// get video filename to request:
		VideoFileName = "movie.Mjpeg";
		

		// Establish a TCP connection with the server to exchange RTSP messages
		// ------------------
		try {
			theClient.RTSPsocket = new Socket(ServerIPAddr, RTSP_server_port);

			// Set input and output stream filters:
			RTSPBufferedReader = new BufferedReader(new InputStreamReader(
					theClient.RTSPsocket.getInputStream()));
			RTSPBufferedWriter = new BufferedWriter(new OutputStreamWriter(
					theClient.RTSPsocket.getOutputStream()));

			// init RTSP state:
			state = INIT;
		} catch (ConnectException e) {
			System.out.println("Could not connect to '" + ServerHost + ":"
					+ RTSP_server_port + "'");
			System.exit(0);
		}
	}

	// ------------------------------------
	// Handler for buttons
	// ------------------------------------

	// .............
	// TO COMPLETE
	// .............

	// Handler for Setup button
	// -----------------------
	class setupButtonListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {

			// System.out.println("Setup Button pressed !");

			if (state == INIT) {
				// Init non-blocking RTPsocket that will be used to receive data
				try {
					// construct a new DatagramSocket to receive RTP packets
					// from the server, on port RTP_RCV_PORT
					RTPsocket = new DatagramSocket(RTP_RCV_PORT);
					// set TimeOut value of the socket to 5msec.
					RTPsocket.setSoTimeout(5);

					RTPsocket_info = new DatagramSocket(RTP_RCV_PORT_INFO);
					// set TimeOut value of the socket to 5msec.
					RTPsocket_info.setSoTimeout(5);

				} catch (SocketException se) {
					System.out.println("Socket exception: " + se);
					System.exit(0);
				}

				// init RTSP sequence number
				RTSPSeqNb = 1;

				// Send SETUP message to the server
				send_RTSP_request("SETUP");

				// Wait for the response
				if (parse_server_response() != 200)
					System.out.println("Invalid Server Response");
				else {
					// change RTSP state and print new state
					state = READY;
					// EN_STATE = DHON;
					// System.out.println("New RTSP state: ....");
				}
			}

		}
	}

	// Handler for Play button
	// -----------------------
	class playButtonListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {

			// System.out.println("Play Button pressed !");
			if (state == READY) {
				// increase RTSP sequence number
				RTSPSeqNb++;

				// Send PLAY message to the server
				send_RTSP_request("PLAY");

				// Wait for the response
				if (parse_server_response() != 200)
					System.out.println("Invalid Server Response");
				else {
					// change RTSP state and print out new state
					state = PLAYING;
					// System.out.println("New RTSP state: ...")

					// start the timer
					timer.start();
				}
			}// else if state != READY then do nothing
		}
	}

	// Handler for Pause button
	// -----------------------
	class pauseButtonListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {

			// System.out.println("Pause Button pressed !");

			if (state == PLAYING) {
				// increase RTSP sequence number
				RTSPSeqNb++;

				// Send PAUSE message to the server
				send_RTSP_request("PAUSE");

				// Wait for the response
				if (parse_server_response() != 200)
					System.out.println("Invalid Server Response");
				else {
					// change RTSP state and print out new state
					state = READY;
					// System.out.println("New RTSP state: ...");

					// stop the timer
					timer.stop();
				}
			}
			// else if state != PLAYING then do nothing
		}
	}

	// Handler for Teardown button
	// -----------------------
	class tearButtonListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {

			// System.out.println("Teardown Button pressed !");

			// increase RTSP sequence number
			RTSPSeqNb++;

			// Send TEARDOWN message to the server
			send_RTSP_request("TEARDOWN");

			// Wait for the response
			if (parse_server_response() != 200)
				System.out.println("Invalid Server Response");
			else {
				// change RTSP state and print out new state
				state = INIT;
				// System.out.println("New RTSP state: ...");

				// stop the timer
				timer.stop();

				// exit
				System.exit(0);
			}
		}
	}

	// ------------------------------------
	// Handler for timer
	// ------------------------------------

	class timerListener implements ActionListener {
		public void actionPerformed(ActionEvent e) {

			// Construct a DatagramPacket to receive data from the UDP socket
			byte[] ReceiveData = new byte[16];
			
			rcvdp_info = new DatagramPacket(ReceiveData, ReceiveData.length);
			rcvdp = new DatagramPacket(buf, buf.length);

			int i,j;
			byte[] receivedDataDecrypted = new byte[15008];
			byte[] receivedInfoDecrypted = new byte[1024];

			try {
				// receive the DP from the socket:
				RTPsocket_info.receive(rcvdp_info);

				RTPsocket.receive(rcvdp);
				RTPpacket rtp_packet;
				int image_length;
				int payload_length;
				byte[] payload;

				if (EN_STATE == DHON) {
					String info;
					System.out.println("-------------------------------------------------------");
					System.out.println("-------------------[ FRAME " + imagenb + " ]-------------------------");
					System.out.println("-------------------------------------------------------");
					
					System.out.println("before " + Arrays.toString(rcvdp_info.getData()));
					// System.out.println("before " + rcvdp_info.getLength());
					receivedInfoDecrypted = aes_decrypt(rcvdp_info.getData(), encryptionKey);
					if (imagenb > 0 && imagenb <= show_hash_until) {
						System.out.println("Hash (SHA-256) : " + MyHash.getSHA256( receivedInfoDecrypted ));
					}
					System.out.println("after " + Arrays.toString(receivedInfoDecrypted));
					info = new String(receivedInfoDecrypted);
					info = info.replace(info.substring(info.length() - 1), "");
					// load received video frame data
					rtp_packet = new RTPpacket(rcvdp.getData(), rcvdp.getLength());
					try {
						payload_length = Integer.parseInt(info);
					} catch (Exception exc) {
						payload_length = 6000;
					}
					// System.out.println("l: " + rtp_packet.getpayload_length());
					payload = new byte[rtp_packet.getpayload_length()];
					rtp_packet.getpayload(payload);

					// add padding before decrypting (Padding required by AES decryptor if data length less than multiply of 16)
					byte[] padded = new byte[15008];
					int num_pad = padded.length - payload.length;
					byte pad = (byte) num_pad;
					Arrays.fill( padded, pad );
					for (int s=0; s<payload.length; s++){
						padded[s] = payload[s];
					}
					// System.out.println("padded: " + padded.length);
					// decrypt video frame data
					receivedDataDecrypted = aes_decrypt(padded, encryptionKey);
					// reassign payload
					payload = receivedDataDecrypted;
					System.out.println("received packet bytes: " + payload);
					imagenb++;
				} else {
					// create an RTPpacket object from the DP
					System.out.println("-------------------------------------------------------");
					System.out.println("-------------------[ FRAME " + imagenb + " ]-------------------------");
					System.out.println("-------------------------------------------------------");
					System.out.println("before " + Arrays.toString(rcvdp_info.getData()));
					System.out.println("after " + Arrays.toString(rcvdp_info.getData()));
					rtp_packet = new RTPpacket(rcvdp.getData(), rcvdp.getLength());
					// print important header fields of the RTP packet received:
					/*System.out.println("Got RTP packet with SeqNum # "
							+ rtp_packet.getsequencenumber() + " TimeStamp "
							+ rtp_packet.gettimestamp() + " ms, of type "
							+ rtp_packet.getpayloadtype());*/

					// print header bitstream:
					// rtp_packet.printheader();

					// get the payload bitstream from the RTPpacket object
					payload_length = rtp_packet.getpayload_length();
					payload = new byte[payload_length];
					rtp_packet.getpayload(payload);
					System.out.println("received packet bytes: " + payload);
					imagenb++;
				}

				// System.out.println("payload: " + payload);
				System.out.println("received packet length: " + payload_length);


				// get an Image object from the payload bitstream
				Toolkit toolkit = Toolkit.getDefaultToolkit();
				Image image = toolkit.createImage(payload, 0, payload_length);


				// display the image as an ImageIcon object
				icon = new ImageIcon(image);
				iconLabel.setIcon(icon);
				LossData = 0;
			} catch (InterruptedIOException iioe) {
				// System.out.println("Nothing to read");
				LossData = 1;
			} catch (IOException ioe) {
				System.out.println("Exception caught: " + ioe);
				LossData = 1;
			} catch (Throwable t) {
				t.printStackTrace();
				LossData = 1;
			}
			
			// try {
			// 	String packet_loss_bits = String.valueOf(LossData);
			// 	packet_loss = new DatagramPacket(packet_loss_bits.getBytes(), packet_loss_bits.length(), ServerIPAddr, 23000);
			// 	RTPsocket_info.send(packet_loss);
			// } catch (Throwable t) {
			// 	t.printStackTrace();
			// }
		}
	}

	// ------------------------------------
	// Parse Server Response
	// ------------------------------------
	private int parse_server_response() {
		int reply_code = 0;

		try {
			// parse status line and extract the reply_code:
			String StatusLine = RTSPBufferedReader.readLine();
			// System.out.println("RTSP Client - Received from Server:");
			System.out.println("StatusLine: 5w0" + StatusLine);

			StringTokenizer tokens = new StringTokenizer(StatusLine);
			tokens.nextToken(); // skip over the RTSP version
			reply_code = Integer.parseInt(tokens.nextToken());

			// if reply code is OK get and print the 2 other lines
			if (reply_code == 200) {
				String SeqNumLine = RTSPBufferedReader.readLine();
				System.out.println("SeqNumLine: " + SeqNumLine);

				String SessionLine = RTSPBufferedReader.readLine();
				System.out.println("SessionLine: " + SessionLine);

				// if state == INIT gets the Session Id from the SessionLine
				tokens = new StringTokenizer(SessionLine);
				tokens.nextToken(); // skip over the Session:
				RTSPid = Integer.parseInt(tokens.nextToken());
			}
		} catch (Exception ex) {
			System.out.println("Exception caught: " + ex);
			System.exit(0);
		}

		return (reply_code);
	}

	// ------------------------------------
	// Send RTSP Request
	// ------------------------------------

	// .............
	// TO COMPLETE
	// .............

	private void send_RTSP_request(String request_type) {
		try {
			// Use the RTSPBufferedWriter to write to the RTSP socket

			// write the request line::
			RTSPBufferedWriter.write(request_type + " " + VideoFileName
					+ " RTSP/1.0" + CRLF);
			// write the CSeq line:
			RTSPBufferedWriter.write("CSeq: " + RTSPSeqNb + CRLF);

			// check if request_type is equal to "SETUP" and in this case write
			// the Transport: line advertising to the server the port used to
			// receive the RTP packets RTP_RCV_PORT
			if (request_type.equals("SETUP")) {
				RTSPBufferedWriter.write("Transport: RTP/UDP; client_port= "
						+ RTP_RCV_PORT + CRLF);

				// otherwise, write the Session line from the RTSPid field
			} else {
				RTSPBufferedWriter.write("Session: " + RTSPid + CRLF);
			}

			RTSPBufferedWriter.flush();
		} catch (Exception ex) {
			System.out.println("Exception caught: " + ex);
			System.exit(0);
		}
	}

	// # AES-Rijndael ENCRYPTION
	public  byte[] aes_decrypt(byte[] ciphertext, String B_shared_key) throws  NoSuchAlgorithmException, InvalidKeyException, Throwable {
        byte[] clearText;
        byte[] cipherText = new byte[ciphertext.length];
		String IV = "AAAAAAAAAAAAAAAA";

        int length=B_shared_key.length();
		// check key length
        if(length>16 && length!=16){
            B_shared_key=B_shared_key.substring(0, 16);
        }
        if(length<16 && length!=16){
            for(int i=0;i<16-length;i++){
                B_shared_key=B_shared_key+"0";
            }
        }
		// System.out.println("Key: " + Arrays.toString(B_shared_key.getBytes()));


        try {
            int counter = 0;
            while (counter < ciphertext.length) {
                cipherText[counter] = (byte)ciphertext[counter];
                counter++;
            }
            Cipher aes = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
            SecretKeySpec aesKey = new SecretKeySpec(B_shared_key.getBytes("UTF-8"), "AES");
            aes.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(IV.getBytes("UTF-8")));
            clearText = aes.doFinal(cipherText);
            // System.out.println(new String(clearText, "ASCII"));
            return clearText;
        } catch (NoSuchAlgorithmException e) {
            System.out.println("E: NoSuchAlgorithmException");
			e.printStackTrace();
            return null;
        } catch (InvalidKeyException e) {
			System.out.println("E: InvalidKeyException");
			e.printStackTrace();
            return null;
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		} catch(Throwable t) {
			t.printStackTrace();
			return null;
		}


    }

}// end of Class ClientPublic
