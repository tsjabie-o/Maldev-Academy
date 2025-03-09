#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#include <stdio.h>

#pragma comment( lib, "ws2_32.lib" )

ULONG GetCurrentIpAddress()
{
    INTERFACE_INFO Interfaces[ 10 ] = { 0 };
	WSADATA 	   Data				= { 0 };
	SOCKET		   Socket		    = { 0 };
	PSOCKADDR_IN   SockAddr			= { 0 };
    ULONG		   AddressIp		= { 0 };
	ULONG		   Length           = { 0 };

	RtlSecureZeroMemory( &Interfaces, sizeof( Interfaces ) );

	//
	// startup the wsa socket 
	//
	if ( WSAStartup( MAKEWORD( 2, 2 ), &Data ) != 0 ) {
		printf( "WSAStartup Failed with Error: %d", WSAGetLastError() );
		goto END;
	}

	//
	// create a socket that we can use to call ioctl on
	//
	if ( ( Socket = WSASocketW( AF_INET, SOCK_DGRAM, 0, 0, 0, 0 ) ) == INVALID_SOCKET ) {
		printf( "WSASocketW Failed with Error: %d", WSAGetLastError() );
	    goto END;
	}

	//
	// send an Ioctl request to get list of
	// adapters and get the size to allocate
	//
	if ( WSAIoctl( Socket, SIO_GET_INTERFACE_LIST, 0, 0, &Interfaces, sizeof( Interfaces ), &Length, 0, 0 ) != 0 ) {
		printf( "WSAIoctl Failed with Error: %d", WSAGetLastError() );
	    goto END;
	}

	//
	// iterate over all adapters and
	// get the current ip address 
	//
	for ( int i = 0; i < ARRAYSIZE( Interfaces ); i++ ) {
		//
		// sanity check that its not a loopback address
		//
	    if (  ( Interfaces[ i ].iiFlags & IFF_UP ) &&
			! ( Interfaces[ i ].iiFlags & IFF_LOOPBACK ) ) 
		{
		    AddressIp = Interfaces[ i ].iiAddress.AddressIn.sin_addr.S_un.S_addr;
			break;
	    }
	}

END:
	WSACleanup();

	return AddressIp;
}

BOOL CheckCurrentAddressInRange( ULONG IpStart, ULONG IpEnd )
{
	ULONG IpAddress = { 0 };

	IpAddress = GetCurrentIpAddress();

	return ( ( IpAddress >= IpStart ) && ( IpAddress < IpEnd ) );
}

int main()
{
	PSTR Start = "192.168.0.100";
	PSTR End   = "192.168.0.200";
	
	printf( "GetCurrentIpAddress() -> %s\n", inet_ntoa( (struct in_addr){ .S_un.S_addr = GetCurrentIpAddress() } ) );

    printf( "CheckCurrentAddressInRange( %s, %s ) -> %s\n", Start, End, CheckCurrentAddressInRange( inet_addr( Start ), inet_addr( End ) ) ? "TRUE" : "FALSE" );

	//
	// lets use address that are most likely
	// not in my local ip address range 
	//
	Start = "192.168.200";
	End   = "192.168.210";

    printf( "CheckCurrentAddressInRange( %s, %s ) -> %s\n", Start, End, CheckCurrentAddressInRange( inet_addr( Start ), inet_addr( End ) ) ? "TRUE" : "FALSE" );
}