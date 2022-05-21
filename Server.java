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
import javax.crypto.spec.IvParameterSpec;

import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.util.Base64;

import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import java.security.spec.InvalidKeySpecException;
import java.lang.Throwable;

public class Server extends JFrame {

    private String str_B_shared_key;

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

	// Encryption
	private static String encryptionKey = "AESEncryption123";

	// RTP variables:
	// ----------------
	DatagramSocket RTPsocket; // socket to be used to send and receive UDP
								// packets
	DatagramSocket RTPsocket_info; // socket to be used to send and receive UDP
	DatagramSocket RTPsocket_hash; // socket to be used to send and receive UDP
								// packets
    private  DatagramPacket rcvdp_info; //UDP packet received from the server

	DatagramPacket senddp; // UDP packet containing the video frames
	DatagramPacket senddp_info, senddp_hash; // UDP packet containing the video frames

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
	Timer timer1; // timer used to send the images at the video frame rate

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

	int image_length;

	static int show_hash_until = -1;
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
						image_length = video.getnextframe(buf);
						RTPpacket rtp_packet;

						// encrypt
						byte[] EN_buf = new byte[buf.length];
						if(EN_STATE == DHON) {
							EN_buf = aes_encrypt(buf, encryptionKey);
							rtp_packet = new RTPpacket(MJPEG_TYPE, imagenb, imagenb * FRAME_PERIOD, EN_buf, EN_buf.length);
							System.out.println("-------------------------------------------------------");
							System.out.println("-------------------[ FRAME " + imagenb + " ]-------------------------");
							System.out.println("-------------------------------------------------------");
							System.out.println("sent packet bytes: " + EN_buf);
							System.out.println("sent packet bytes length: " + rtp_packet.getlength());
						} else {
							// Builds an RTPpacket object containing the frame
							rtp_packet = new RTPpacket(MJPEG_TYPE, imagenb, imagenb * FRAME_PERIOD, buf, image_length);
							System.out.println("sent packet bytes: " + buf);
							System.out.println("sent packet bytes length: " + rtp_packet.getlength());
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

		ActionListener infoListener = new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                if (imagenb < VIDEO_LENGTH) {
					// update current imagenb
					byte[] Loss = new byte[8];
					rcvdp_info = new DatagramPacket(Loss, Loss.length);

					try {
						

						if(EN_STATE == DHON) {
							String packet_info_bits = String.valueOf(image_length);
							String num_pad = Integer.toHexString(16 - packet_info_bits.length());
							for (int s=packet_info_bits.length(); s<16; s++){
								packet_info_bits += num_pad;
							}
							String hash = MyHash.getSHA256(packet_info_bits.getBytes());
							// System.out.println("before " + packet_info_bits);
							byte[] EN_buf = new byte[packet_info_bits.length()];
							System.out.println("before " + Arrays.toString(packet_info_bits.getBytes()));
							// if (imagenb > 0 && imagenb <= show_hash_until) {
							// 	System.out.println("Hash (SHA-256) : " + hash);
							// }
							EN_buf = aes_encrypt(packet_info_bits.getBytes(), encryptionKey);
							System.out.println("after " + Arrays.toString(EN_buf));
							System.out.println("image_length " + image_length);
							// System.out.println("EN_buf " + EN_buf);
							senddp_info = new DatagramPacket(EN_buf, EN_buf.length, ClientIPAddr, 20000);
							senddp_hash = new DatagramPacket(hash.getBytes(), hash.length(), ClientIPAddr, 20111);

							RTPsocket_info.send(senddp_info);
							RTPsocket_hash.send(senddp_hash);
							System.out.println("sent info bytes: " + new String(EN_buf));
						} else {
							String packet_info_bits = String.valueOf(image_length);
							String hash = MyHash.getSHA256(packet_info_bits.getBytes());
							System.out.println("image_length" + packet_info_bits);
							senddp_info = new DatagramPacket(packet_info_bits.getBytes(), packet_info_bits.length(), ClientIPAddr, 20000);
							senddp_hash = new DatagramPacket(hash.getBytes(), hash.length(), ClientIPAddr, 20111);

							RTPsocket_info.send(senddp_info);
							RTPsocket_hash.send(senddp_hash);
							System.out.println("sent info bytes: " + packet_info_bits);
						}

					} catch (Exception ex) {
						System.out.println("Exception caught: " + ex);
						ex.printStackTrace();
						System.exit(0);
					} catch (Throwable t) {
						t.printStackTrace();
					}
				} else {
					// if we have reached the end of the video file, stop the timer
					if (timer1 != null)  timer1.stop();
				}
            }
        };

		// init Timer
		timer = new Timer(FRAME_PERIOD, videoStreamer);
		timer.setInitialDelay(0);
		timer.setCoalesce(true);

		timer1 = new Timer(FRAME_PERIOD, infoListener);
		timer1.setInitialDelay(0);
		timer1.setCoalesce(true);

		// allocate memory for the sending buffer
		buf = new byte[15008];

		// Handler to close the main window
		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				// stop the timer and exit
				timer.stop();
				timer1.stop();
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
		if (argv.length >= 2) 
			encryptionKey = String.valueOf(argv[1]);
		
		if (argv.length >= 3) 
			show_hash_until = Integer.parseInt(argv[2]);

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
					// EN_STATE = CLEAR;
					EN_STATE = DHON;

					// init the VideoStream object:
					theServer.video = new VideoStream(VideoFileName);

					// init RTP socket
					theServer.RTPsocket = new DatagramSocket();
					theServer.RTPsocket_info = new DatagramSocket(23000);
					theServer.RTPsocket_hash = new DatagramSocket(24111);
				}
			}

			// loop to handle RTSP requests
			while (true) {
				// parse the request
				request_type = theServer.parse_RTSP_request(); // blocking

				if ((request_type == PLAY) && (state == READY)) {
					// send back response
					theServer.send_RTSP_response();
					// start timer
					theServer.timer.start();
					theServer.timer1.start();
					// update state
					state = PLAYING;
					System.out.println("New RTSP state: PLAYING");
				} else if ((request_type == PAUSE) && (state == PLAYING)) {
					// send back response
					theServer.send_RTSP_response();
					// stop timer
					theServer.timer.stop();
					theServer.timer1.stop();
					// update state
					state = READY;
					System.out.println("New RTSP state: READY");
				} else if (request_type == TEARDOWN) {
					// send back response
					theServer.send_RTSP_response();
					// stop timer
					theServer.timer.stop();
					theServer.timer1.stop();
					// close sockets
					theServer.RTSPsocket.close();
					theServer.RTPsocket.close();
					theServer.RTPsocket_info.close();
					theServer.RTPsocket_hash.close();

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
			else if ((new String(request_type_string)).compareTo("PLAY") == 0)
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
			tokens.nextToken();
			RTSPSeqNb = Integer.parseInt(tokens.nextToken());

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

	public  byte[] aes_encrypt(byte[] clearText, String B_shared_key) throws  NoSuchAlgorithmException, InvalidKeyException, Throwable {
        byte[] clearText_;
        byte[] cipherText;
        byte[] returnText = new byte[clearText.length];
		String IV = "AAAAAAAAAAAAAAAA";
        int length=B_shared_key.length();
		// System.out.println("B shared Key length : " + length);
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
            Cipher aes = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
            SecretKeySpec aesKey = new SecretKeySpec(B_shared_key.getBytes("UTF-8"), "AES");
            aes.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(IV.getBytes("UTF-8")));
            cipherText = aes.doFinal(clearText);
            // int counter = 0;
            // while (counter < cipherText.length) {
            //     returnText[counter] = cipherText[counter];
            //     counter++;
            // }
            return cipherText;
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
}
