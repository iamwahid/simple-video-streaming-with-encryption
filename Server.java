/* ------------------
 Server
 usage: java Server [RTSP listening port]
 ---------------------- */

import java.io.*;
import java.net.*;
import java.nio.*;
import java.awt.*;
import java.util.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.Timer;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.StringTokenizer;
// import java.util.Timer;
import java.util.TimerTask;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;

import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.util.Base64;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.InvalidKeySpecException;
import java.lang.Throwable;

public class Server extends JFrame {

	static String s_RTSP_ID ; //ID of the RTSP session
    static String s_RTSPSeqNb; //Sequence number of RTSP messages within the session
	private String str_keysize;
    private String str_prime;
    private String str_alpha;
    private String str_A_Pubkey;
    private String str_B_shared_key;
    private String str_M_public_key;
    private String str_Rec_Public_Key;
    static PublicKey Client_RSAPublicKey;

	//rtsp states
    private static int EN_STATE;
    final static int CLEAR = 0;
    final static int DHON = 1;
    final static int RSAON = 2;
    final static int INIT = 0;
    final static int READY = 1;
    final static int PLAYING = 2;
    final static int STOP = 7;
    //rtsp message types
    final static int SETUP = 3;
    final static int PLAY = 4;
    final static int PAUSE = 5;
    final static int TEARDOWN = 6;
    final static int DHSETUP = 8;

	// RTP variables:
	// ----------------
	DatagramSocket RTPsocket; // socket to be used to send and receive UDP
								// packets
	DatagramSocket RTPsocket_info; // socket to be used to send and receive UDP
								// packets

	DatagramPacket senddp; // UDP packet containing the video frames
	DatagramPacket senddp_info; // UDP packet containing the video frames

	InetAddress ClientIPAddr; // Client IP address

	int RTP_dest_port = 0; // destination port for RTP packets (given by the
							// RTSP Client)

	// GUI:
	// ----------------
	JLabel label;

	// Video variables:
	// ----------------
	int imagenb = 0; // image nb of the image currently transmitted

	VideoStream video; // VideoStream object used to access video frames

	static int MJPEG_TYPE = 26; // RTP payload type for MJPEG video

	static int FRAME_PERIOD = 50; // Frame period of the video to stream, in
									// ms

	static int VIDEO_LENGTH = 500; // length of the video in frames

	Timer timer; // timer used to send the images at the video frame rate

	byte[] buf; // buffer used to store the images to send to the client

	static int state; // RTSP Server state == INIT or READY or PLAY

	Socket RTSPsocket; // socket used to send/receive RTSP messages

	// input and output stream filters
	static BufferedReader RTSPBufferedReader;

	static BufferedWriter RTSPBufferedWriter;

	static String VideoFileName; // video file requested from the client

	static int RTSP_ID = 123456; // ID of the RTSP session

	int RTSPSeqNb = 0; // Sequence number of RTSP messages within the session

	final static String CRLF = "\r\n";

	// --------------------------------
	// Constructor
	// --------------------------------
	public Server() {

		// init Frame
		super("Server");

		// ------------------------
		// Handler for timer
		ActionListener videoStreamer = new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                if (imagenb < VIDEO_LENGTH) {
					// update current imagenb
					imagenb++;

					try {
						// get next frame to send from the video, as well as its size
						int image_length = video.getnextframe(buf);
						RTPpacket rtp_packet;

						// encrypt
						byte[] EN_buf;
						if(EN_STATE == DHON) {
							EN_buf = rc4_encrypt(buf, str_B_shared_key);
							// EN_buf = aes_encrypt(buf, str_B_shared_key);
							rtp_packet = new RTPpacket(MJPEG_TYPE, imagenb, imagenb * FRAME_PERIOD, EN_buf, EN_buf.length);
							System.out.println("buf: " + buf);
							System.out.println("EN_buf: " + EN_buf);
						} else {
							// Builds an RTPpacket object containing the frame
							rtp_packet = new RTPpacket(MJPEG_TYPE, imagenb, imagenb * FRAME_PERIOD, buf, image_length);
							// System.out.println("Exception caught: " + image_length);
						}

						// get to total length of the full rtp packet to send
						int packet_length = rtp_packet.getlength();

						// retrieve the packet bitstream and store it in an array of
						// bytes
						byte[] packet_bits = new byte[packet_length];
						rtp_packet.getpacket(packet_bits);

						// send the packet as a DatagramPacket over the UDP socket
						senddp = new DatagramPacket(packet_bits, packet_length,
								ClientIPAddr, RTP_dest_port);
						RTPsocket.send(senddp);

						String packet_info_bits = String.valueOf(image_length);
						senddp_info = new DatagramPacket(packet_info_bits.getBytes(), packet_info_bits.length(), ClientIPAddr, 20000);

						System.out.println("num: " + image_length);
						RTPsocket_info.send(senddp_info);

						System.out.println("Send frame #"+imagenb);
						// print the header bitstream
						// rtp_packeer();

						// update GUI
						label.setText("Send frame #" + imagenb);
					} catch (Exception ex) {
						System.out.println("Exception caught: " + ex);
						System.exit(0);
					} catch (Throwable t) {
						t.printStackTrace();
					}
				} else {
					// if we have reached the end of the video file, stop the timer
					if (timer != null)  timer.stop();
				}
            }
        };

		// init Timer
		timer = new Timer(FRAME_PERIOD, videoStreamer);
		timer.setInitialDelay(0);
		timer.setCoalesce(true);

		// allocate memory for the sending buffer
		buf = new byte[15000];

		// Handler to close the main window
		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				// stop the timer and exit
				timer.stop();
				System.exit(0);
			}
		});

		// GUI:
		label = new JLabel("Send frame #        ", JLabel.CENTER);
		getContentPane().add(label, BorderLayout.CENTER);
	}

	// ------------------------------------
	// main
	// ------------------------------------
	public static void main(String argv[]) throws Exception {
		// create a Server object
		Server theServer = new Server();

		// show GUI:
		theServer.pack();
		theServer.setVisible(true);

		// get RTSP socket port from the command line
		int RTSPport = Integer.parseInt(argv[0]);

		try {
			// Initiate TCP connection with the client for the RTSP session
			ServerSocket listenSocket = new ServerSocket(RTSPport);
			theServer.RTSPsocket = listenSocket.accept();
			listenSocket.close();

			// Get Client IP address
			theServer.ClientIPAddr = theServer.RTSPsocket.getInetAddress();

			// Initiate RTSPstate
			state = INIT;

			// Set input and output stream filters:
			RTSPBufferedReader = new BufferedReader(new InputStreamReader(
					theServer.RTSPsocket.getInputStream()));
			RTSPBufferedWriter = new BufferedWriter(new OutputStreamWriter(
					theServer.RTSPsocket.getOutputStream()));

			// Wait for the SETUP message from the client
			int request_type;
			boolean done = false;
			while (!done) {
				request_type = theServer.parse_RTSP_request(); // blocking

				if (request_type == SETUP) {
					done = true;

					// update RTSP state
					state = READY;
					System.out.println("New RTSP state: READY");

					// Send response
					theServer.send_RTSP_response();
					EN_STATE = CLEAR;

					// init the VideoStream object:
					theServer.video = new VideoStream(VideoFileName);

					// init RTP socket
					theServer.RTPsocket = new DatagramSocket();
					theServer.RTPsocket_info = new DatagramSocket(23000);
				}
			}

			// loop to handle RTSP requests
			while (true) {
				// parse the request
				request_type = theServer.parse_RTSP_request(); // blocking

				// request = DHSETUP
				if (request_type == DHSETUP) {
					// done = true;

					//update RTSP state
					state = READY;
					System.out.println("New RTSP state: DH READY");

					//Send response
					theServer.DH_Process_send_RTSP_response();
					EN_STATE = DHON;

					//init the VideoStream object

				}
				// DHSETUP end

				if ((request_type == PLAY) && (state == READY)) {
					// send back response
					theServer.send_RTSP_response();
					// start timer
					theServer.timer.start();
					// update state
					state = PLAYING;
					System.out.println("New RTSP state: PLAYING");
				} else if ((request_type == PAUSE) && (state == PLAYING)) {
					// send back response
					theServer.send_RTSP_response();
					// stop timer
					theServer.timer.stop();
					// update state
					state = READY;
					System.out.println("New RTSP state: READY");
				} else if (request_type == TEARDOWN) {
					// send back response
					theServer.send_RTSP_response();
					// stop timer
					theServer.timer.stop();
					// close sockets
					theServer.RTSPsocket.close();
					theServer.RTPsocket.close();
					theServer.RTPsocket_info.close();

					System.exit(0);
				}
			}
		} catch (BindException e) {
			System.out.println("Could not init server on port '" + argv[0] + "'");
			System.exit(0);
		}

	}

	// ------------------------------------
	// Parse RTSP Request
	// ------------------------------------
	private int parse_RTSP_request() {
		int request_type = -1;
		try {
			// parse request line and extract the request_type:
			String RequestLine = RTSPBufferedReader.readLine();
			// System.out.println("RTSP Server - Received from Client:");
			System.out.println(RequestLine);

			StringTokenizer tokens = new StringTokenizer(RequestLine);
			String request_type_string = tokens.nextToken();

			// convert to request_type structure:
			if ((new String(request_type_string)).compareTo("SETUP") == 0)
				request_type = SETUP;
			else if ((new String(request_type_string)).compareTo("DHSETUP") == 0) {
				request_type = DHSETUP;
                str_keysize = tokens.nextToken();
                str_prime = tokens.nextToken();
			} else if ((new String(request_type_string)).compareTo("PLAY") == 0)
				request_type = PLAY;
			else if ((new String(request_type_string)).compareTo("PAUSE") == 0)
				request_type = PAUSE;
			else if ((new String(request_type_string)).compareTo("TEARDOWN") == 0)
				request_type = TEARDOWN;

			if (request_type == SETUP) {
				// extract VideoFileName from RequestLine
				VideoFileName = tokens.nextToken();
			}

			// parse the SeqNumLine and extract CSeq field
			String SeqNumLine = RTSPBufferedReader.readLine();
			System.out.println(SeqNumLine);
			tokens = new StringTokenizer(SeqNumLine);
			if ((new String(request_type_string)).compareTo("DHSETUP") == 0) {
                tokens.nextToken();
                str_alpha = tokens.nextToken();
            } else {
                tokens.nextToken();
                RTSPSeqNb = Integer.parseInt(tokens.nextToken());
            }

			// get LastLine
			String LastLine = RTSPBufferedReader.readLine();
			System.out.println(LastLine);

			if (request_type == SETUP) {
				// extract RTP_dest_port from LastLine
				tokens = new StringTokenizer(LastLine);
				for (int i = 0; i < 3; i++)
					tokens.nextToken(); // skip unused stuff
				RTP_dest_port = Integer.parseInt(tokens.nextToken());
				System.out.println("RTP_dest_port : "+ RTP_dest_port);
			}

			if (request_type == DHSETUP)
            {
                //extract RTP_dest_port from LastLine
                tokens = new StringTokenizer(LastLine);

                tokens.nextToken(); //skip unused stuff
                str_A_Pubkey = tokens.nextToken();
				System.out.println(str_A_Pubkey);
            }
			// else LastLine will be the SessionId line ... do not check for
			// now.
		} catch (Exception ex) {
			System.out.println("Exception caught: " + ex);
			System.exit(0);
		}
		return (request_type);
	}

	// ------------------------------------
	// Send RTSP Response
	// ------------------------------------
	private void send_RTSP_response() {
		try {
			RTSPBufferedWriter.write("RTSP/1.0 200 OK" + CRLF);
			RTSPBufferedWriter.write("CSeq: " + RTSPSeqNb + CRLF);
			RTSPBufferedWriter.write("Session: " + RTSP_ID + CRLF);
			RTSPBufferedWriter.flush();
			// System.out.println("RTSP Server - Sent response to Client.");
		} catch (Exception ex) {
			System.out.println("Exception caught: " + ex);
			System.exit(0);
		}
	}

	private static BigInteger getSharedKey(PublicKey pubKey, PrivateKey privKey) throws NoSuchAlgorithmException, InvalidKeyException {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(privKey);
        ka.doPhase(pubKey, true);
        byte[] b = ka.generateSecret();
        BigInteger secretKey = new BigInteger(b);
        return secretKey;
    }

	//------------------------------------
    //Send DH RTSP Response
    //------------------------------------
    private void DH_Process_send_RTSP_response()
    {

        try{
            BigInteger prime = new BigInteger(str_prime);
            BigInteger alpha = new BigInteger(str_alpha);
            KeyPairGenerator bkpg = KeyPairGenerator.getInstance("DH");
            DHParameterSpec param = new DHParameterSpec(prime, alpha);
            bkpg.initialize(param);
            KeyPair B_kp = bkpg.generateKeyPair(); //public key (Yb) and private key (Xb) of B
            System.out.println("VR: Keypair OK");
            byte[] publicBytes = Base64.getDecoder().decode(str_A_Pubkey.getBytes());
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            PublicKey A_publicKey = keyFactory.generatePublic(keySpec);
            final BigInteger B_SharedSecret = getSharedKey(A_publicKey, B_kp.getPrivate());
            str_B_shared_key = B_SharedSecret.toString();
            //send blind key
            System.out.println("VS: S's shared DH key = " + str_B_shared_key);
            final BigInteger B_PubKey = ((DHPublicKey) B_kp.getPublic()).getY();
            final String S_B_PubKey = Base64.getEncoder().encodeToString(B_kp.getPublic().getEncoded());
            // final String reply_message = "2" + "$$" + S_B_PubKey + "$$1111" +CRLF;

            RTSPBufferedWriter.write("RTSP/1.0 200 OK"+'\n');
            RTSPBufferedWriter.flush();
            RTSPBufferedWriter.write("CSeq: " + S_B_PubKey + '\n');
            RTSPBufferedWriter.flush();
            s_RTSP_ID= String.valueOf(RTSP_ID);
            RTSPBufferedWriter.write("Session: " + s_RTSP_ID + '\n');
            RTSPBufferedWriter.flush();
            System.out.println("VR: after RTSPBufferedWriter.write(Session:  + RTSP_ID + CRLF)  ");
            //System.out.println("RTSP Server - Sent response to Client.");
        }
        catch(Exception ex)
        {
            System.out.println("Exception caught: "+ex);
            // System.exit(0);
        }
    }

	public  byte[] aes_encrypt(byte[] clearText, String B_shared_key) throws  NoSuchAlgorithmException, InvalidKeyException, Throwable {
        byte[] clearText_;
        byte[] cipherText;
        byte[] returnText = new byte[clearText.length];
        int length=B_shared_key.length();
		System.out.println("B shared Key length : " + length);
        if(length>16 && length!=16){
            B_shared_key=B_shared_key.substring(0, 15);
        }
        if(length<16 && length!=16){
            for(int i=0;i<16-length;i++){
                B_shared_key=B_shared_key+"0";
            }
        }

        try {
            Cipher aes = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
            SecretKeySpec aesKey = new SecretKeySpec(B_shared_key.getBytes(), "AES");
            aes.init(Cipher.ENCRYPT_MODE, aesKey);
            cipherText = aes.update(clearText);
            int counter = 0;
            while (counter < cipherText.length) {
                returnText[counter] = cipherText[counter];
                counter++;
            }
            return returnText;
        } catch (NoSuchAlgorithmException e) {
            System.out.println("E: NoSuchAlgorithmException");
            return null;
        } catch (InvalidKeyException e) {
			System.out.println("E: InvalidKeyException");
            return null;
		} catch (Exception e) {
			return null;
		} catch(Throwable t) {
			return null;
		}
    }

	public byte[] rc4_encrypt(byte[] clearText, String B_shared_key)throws  NoSuchAlgorithmException, InvalidKeyException, Throwable {
        byte[] clearText_;
        byte[] cipherText;
        byte[] returnText = new byte[clearText.length];
        int length=B_shared_key.length();
        if(length>16 && length!=16){
            B_shared_key=B_shared_key.substring(0, 15);
        }
        if(length<16 && length!=16){
            for(int i=0;i<16-length;i++){
                B_shared_key=B_shared_key+"0";
            }
        }

        try {
            Cipher rc4 = Cipher.getInstance("RC4");
            SecretKeySpec rc4Key = new SecretKeySpec(B_shared_key.getBytes(), "RC4");
            rc4.init(Cipher.ENCRYPT_MODE, rc4Key);
            cipherText = rc4.update(clearText);
            int counter = 0;
            while (counter < cipherText.length) {
                returnText[counter] = cipherText[counter];
                counter++;
            }
            return returnText;
        } catch (Exception e) { return null; }
    }
}
