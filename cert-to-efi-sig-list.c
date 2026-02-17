#include <stdint.h>
#include <efi.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include <guid.h>
#include <efiauthenticated.h>

static void usage()
{
	printf("Usage: cert-to-efi-sig-list [-g <guid>] <crt file> <efi sig list file>\n");
}

static void help()
{
	usage();
	printf("Take an input X509 certificate (in PEM format) and convert it to an EFI\n"
	       "signature list file containing only that single certificate\n\n"
	       "Options:\n"
	       "\t-g <guid>        Use <guid> as the owner of the signature. If this is not\n"
	       "\t                 supplied, an all zero guid will be used\n"

	       );
	
}

int main(int argc, char *argv[])
{
	char *certfile, *efifile;
	EFI_GUID owner;
	memset(&owner, 0, sizeof(EFI_GUID));

	while (argc > 1) {
		if (strcmp("--help", argv[1]) == 0) {
			help();
			exit(0);
		} else if (strcmp("-g", argv[1]) == 0) {
			if (str_to_guid(argv[2], &owner)) {
				printf("invalid guid\n");
				exit(1);
			}
			argv += 2;
			argc -= 2;
		} else {
			break;
		}
	}
	  

	if (argc != 3) {
		usage();
		exit(1);
	}

	certfile = argv[1];
	efifile = argv[2];

	BIO *cert_bio = BIO_new_file(certfile, "r");
	X509 *cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL);
	unsigned char *PkCert = NULL;
	uint32_t PkCertLen = i2d_X509(cert, &PkCert);

	uint32_t signature_size = PkCertLen + sizeof(EFI_GUID);
	uint32_t result_size = PkCertLen + 2 * sizeof(EFI_GUID) + 3 * sizeof(uint32_t);
	unsigned char *result = malloc(result_size);
	EFI_GUID signatureType = EFI_CERT_X509_GUID;

	// EFI_SIGNATURE_LIST.SignatureType
	// Type of the signature. GUID signature types are defined in “Related Definitions” below.
	memcpy(result, &signatureType, sizeof(EFI_GUID));

	// EFI_SIGNATURE_LIST.SignatureListSize
	// Total size of the signature list, including this header.
	memcpy(result + sizeof(EFI_GUID),
		&result_size, sizeof(uint32_t));

	// EFI_SIGNATURE_LIST.SignatureHeaderSize
	// Size of the signature header which precedes the array of signatures.
	memset(result + sizeof(EFI_GUID) + sizeof(uint32_t), 0, sizeof(uint32_t));

	// EFI_SIGNATURE_LIST.SignatureSize
	// Size of each signature. Must be at least the size of EFI_SIGNATURE_DATA.
	memcpy(result + sizeof(EFI_GUID) + 2 * sizeof(uint32_t),
		&signature_size, sizeof(uint32_t));

	// EFI_SIGNATURE_LIST.Signatures[0].SignatureOwner
	// An identifier which identifies the agent which added the signature to the list.
	memcpy(result + sizeof(EFI_GUID) + 3 * sizeof(uint32_t),
		&owner, sizeof(EFI_GUID));

	// EFI_SIGNATURE_LIST.Signatures[0].SignatureData
	memcpy(result + 2 * sizeof(EFI_GUID) + 3 * sizeof(uint32_t),
		PkCert, PkCertLen);

	FILE *f = fopen(efifile, "w");
	if (!f) {
		fprintf(stderr, "failed to open efi file %s: ", efifile);
		exit(1);
	}
	if (fwrite(result, 1, result_size, f) != result_size) {
		fprintf(stderr, "Did not write enough bytes to efi file");
		exit(1);
	}

	OPENSSL_free(PkCert);
	free(result);

	return 0;
}
