#include<GL/glut.h>
#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>
#include<math.h>
#include"src/SOIL.h"

#define		mainmenu		100
#define  keygeny         0
#define   transmitkey   1
#define  encrypt		2
#define  decrypt    3
#define  exite		4

#define ACCURACY 5
#define SINGLE_MAX 10000
#define EXPONENT_MAX 1000



int flag=0,flag1=0;
int p, q, n, phi, e, d, bytes, len;
int *encoded, *decoded;
char string[20],buffer[256];
GLuint tex_2d;
GLfloat a=126,b=0,c=0,ang,x2,y2;

void *currentfont;

/**
 * Computes a^b mod c
 */
 /*
 		Russian phesants method--to avoid overflow
		c=a;d=b;r=1;
		while d≠0
		if d is odd then r=(cr) mod m;
		d=d div 2; \\ integer division; one usually right-shifts bits in practice
		c=c^2 mod m;
		endwhile
r
*/
int modpow(long long a, long long b, int c) {
	int res = 1;
	while(b > 0) {
		if(b & 1) {
			res = (res * a) % c;
		}
		b = b >> 1;
		a = (a * a) % c;
	}
	return res;
}

/**
 * Computes the Jacobi symbol, (a, n)
 *Euler proved[1] that for any prime number p and any integer a,
	a^{(p-1)/2} =jacobi(a,p)mod p
	Jacobi(a,n) {
  j := 1
  while (a not 0) do {
    while (a even) do {
      a := a/2
      if (n = 3 (mod 8) or n = 5 (mod 8)) then j := -j
    }
    interchange(a,n)
    if (a = 3 (mod 4) and n = 3 (mod 4)) then j := -j
    a := a mod n
  }
  if (n = 1) then return (j) else return(0)
}
 */
int jacobi(int a, int n) {
	int twos, temp;
	int mult = 1;
	while(a > 1 && a != n) {
		a = a % n;
		if(a <= 1 || a == n) break;
		twos = 0;
		while(a % 2 == 0 && ++twos) a /= 2; /* Factor out multiples of 2 */
		if(twos > 0 && twos % 2 == 1) mult *= (n % 8 == 1 || n % 8 == 7) * 2 - 1;
		if(a <= 1 || a == n) break;
		if(n % 4 != 1 && a % 4 != 1) mult *= -1; /* Coefficient for flipping */
		temp = a;
		a = n;
		n = temp;
	}
	if(a == 0) return 0;
	else if(a == 1) return mult;
	else return 0; /* a == n => gcd(a, n) != 1 */
}

/**
 * Check whether a is a Euler witness for n
 */
int solovayPrime(int a, int n) {
	int x = jacobi(a, n);
	if(x == -1) x = n - 1;
	return x != 0 && modpow(a, (n - 1)/2, n) == x;
}

/**
 * Test if n is probably prime, using accuracy of k (k solovay tests)
 repeat k times:
   choose a randomly in the range [2,n − 1]
   x =a|n
   if x = 0 or a^{(n-1)/2} not equivalent to x pmod n then
      return composite
return probably prime
 */
int probablePrime(int n, int k) {
	if(n == 2) return 1;
	else if(n % 2 == 0 || n == 1) return 0;
	while(k-- > 0) {
		if(!solovayPrime(rand() % (n - 2) + 2, n)) return 0;
	}
	return 1;
}

/**
 * Find a random (probable) prime between 3 and n - 1, this distribution is
 * nowhere near uniform, see prime gaps
 */
int randPrime(int n) {
	int prime = rand() % n;
	n += n % 2; /* n needs to be even so modulo wrapping preserves oddness */
	prime += 1 - prime % 2;
	while(1) {
		if(probablePrime(prime, ACCURACY)) return prime;
		prime = (prime + 2) % n;
	}
}

/**
 * Compute gcd(a, b)
 */
int gcd(int a, int b) {
	int temp;
	while(b != 0) {
		temp = b;
		b = a % b;
		a = temp;
	}
	return a;
}

/**
 * Find a random exponent x between 3 and n - 1 such that gcd(x, phi) = 1,
 * this distribution is similarly nowhere near uniform
 */
int randExponent(int phi, int n) {
	int e = rand() % n;
	while(1) {
		if(gcd(e, phi) == 1) return e;
		e = (e + 1) % n;
		if(e <= 2) e = 3;
	}
}

/**
 * Compute n^-1 mod m by extended euclidian method
 */
int inverse(int n, int modulus) {
	int a = n, b = modulus;
	int x = 0, y = 1, x0 = 1, y0 = 0, q, temp;
	while(b != 0) {
		q = a / b;
		temp = a % b;
		a = b;
		b = temp;
		temp = x; x = x0 - q * x; x0 = temp;
		temp = y; y = y0 - q * y; y0 = temp;
	}
	if(x0 < 0) x0 += modulus;
	return x0;
}

/**
 * Encode the message m using public exponent and modulus, c = m^e mod n
 */
int encode(int m, int e, int n) {
	return modpow(m, e, n);
}

/**
 * Decode cryptogram c using private exponent and public modulus, m = c^d mod n
 */
int decode(int c, int d, int n) {
	return modpow(c, d, n);
}

/**
 * Encode the message of given length, using the public key (exponent, modulus)
 * The resulting array will be of size len/bytes, each index being the encryption
 * of "bytes" consecutive characters, given by m = (m1 + m2*128 + m3*128^2 + ..),
 * encoded = m^exponent mod modulus
 */
int* encodeMessage(int len, int bytes, char* message, int exponent, int modulus) {
	int *encoded = (int*)malloc((len/bytes)* sizeof(int));
	int x, i, j;
	for(i = 0; i < len; i += bytes) {
		x = 0;
		for(j = 0; j < bytes; j++) x += message[i + j] * (1 << (7 * j));
		encoded[i/bytes] = encode(x, exponent, modulus);
#ifndef MEASURE
	//	printf("%d ", encoded[i/bytes]);
#endif
	}
	return encoded;
}

/**
 * Decode the cryptogram of given length, using the private key (exponent, modulus)
 * Each encrypted packet should represent "bytes" characters as per encodeMessage.
 * The returned message will be of size len * bytes.
 */
int* decodeMessage(int len, int bytes, int* cryptogram, int exponent, int modulus) {
	int *decoded =(int *) malloc(len * bytes * sizeof(int));
	int x, i, j;
	for(i = 0; i < len; i++) {
		x = decode(cryptogram[i], exponent, modulus);
		for(j = 0; j < bytes; j++) {
			decoded[i*bytes + j] = (x >> (7 * j)) % 128;
#ifndef MEASURE
			if(decoded[i*bytes + j] != '\0') printf("%c", decoded[i*bytes + j]);
#endif
		}
	}
	return decoded;
}

void setFont(void *font)
{
	currentfont=font;
}

void drawstring(float x,float y,float z,char *string) //to display text messages
{
	  char *c;
		glRasterPos3f(x,y,z);
		for(c=string;*c!='\0';c++)
		{
			glColor3f(0.0,0.0,0.0);
			glutBitmapCharacter(currentfont,*c);
		}
}

void timer()
{
	a+=20.0;
	glutPostRedisplay();
}

void title()												// to draw the starting screen
{
	glClear(GL_COLOR_BUFFER_BIT);
	glColor3f(1.0,1.0,1.0);

	glEnable(GL_TEXTURE_2D);
	//glColor4f(1.0f, 1.0f, 1.0f, 0.0f);
	tex_2d = SOIL_load_OGL_texture(
			 "f.png",
			 SOIL_LOAD_RGB,
			 SOIL_CREATE_NEW_ID,
			 SOIL_FLAG_NTSC_SAFE_RGB
		 );
	glBindTexture(GL_TEXTURE_2D, tex_2d);
	glTexEnvf(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
				//determint coordinates of the quad on which you will 'load' an image
	glBegin(GL_POLYGON);
	glTexCoord2f(0.0, 0.0);
	glColor3f(0.0,0.1,0.3);
	glVertex2f(500.0,0.0);
	glTexCoord2f(1.0, 0.0);
	glColor3f(0.0,0.5,0.6);
	glVertex2f(0.0,0.0);
	glTexCoord2f(1.0, 1.0);
	glColor3f(0.0,0.5,0.6);
	glVertex2f(0.0,500.0);
	glTexCoord2f(0.0, 1.0);
	glColor3f(0.0,0.1,0.3);
	glVertex2f(500.0,500.0);
	glEnd();
	glDisable(GL_TEXTURE_2D);

	 		setFont(GLUT_BITMAP_TIMES_ROMAN_24);
			glColor3f(1.0,1.0,1.0);
			drawstring(20.0,435.0,1.0,"            RIVEST SHAMIR ADLEMAN ALGORITHM VISUALIZATION      ");
			setFont(GLUT_BITMAP_HELVETICA_18);
			glColor3f(1.0,1.0,1.0);
			drawstring(210.0,365.0,1.0,"		SUBMITTED BY	");
			glColor3f(1.0,1.0,1.0);
			drawstring(180.0,340.0,1.0,"APOORVA SHASTRY 1PE13CS030");
			glColor3f(1.0,1.0,1.0);
			drawstring(180.0,320.0,1.0,"DARA SRAVYA\t\t\t\t\t\t\t\t\t\t\t\t1PE13CS050");
			glColor3f(1.0,1.0,1.0);
			drawstring(400.0,100.0,1.0," Press M -> continue");
			glutSwapBuffers();
}

void draw(int c) // TO DRAW POLYGON FOR DISPLAY MENUS
{
    	glBegin(GL_POLYGON);
				glColor3f(0.0,0.4,0.2);
				glVertex2i(0,425-c);
				glColor3f(0.0,0.4,0.2);
				glVertex2i(100,395-c);
				glColor3f(0.0,0.3,0.2);
				glVertex2i(425,395-c);
				glColor3f(0.0,0.2,0.3);
				glVertex2i(425,425-c);
			glEnd();
			glFlush();
}
void text(void)
{

	glClear(GL_COLOR_BUFFER_BIT);
	glEnable(GL_TEXTURE_2D);
	//glColor4f(1.0f, 1.0f, 1.0f, 0.0f);
	tex_2d = SOIL_load_OGL_texture(
			 "f.png",
			 SOIL_LOAD_RGB,
			 SOIL_CREATE_NEW_ID,
			 SOIL_FLAG_NTSC_SAFE_RGB
		 );
	glBindTexture(GL_TEXTURE_2D, tex_2d);
	glTexEnvf(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
	glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
				//determint coordinates of the quad on which you will 'load' an image
				glBegin(GL_POLYGON);
				glTexCoord2f(0.0, 0.0);
				glColor3f(0.0,0.1,0.3);
				glVertex2f(500.0,0.0);
				glTexCoord2f(1.0, 0.0);
				glColor3f(0.0,0.5,0.6);
				glVertex2f(0.0,0.0);
				glTexCoord2f(1.0, 1.0);
				glColor3f(0.0,0.5,0.6);
				glVertex2f(0.0,500.0);
				glTexCoord2f(0.0, 1.0);
				glColor3f(0.0,0.1,0.3);
				glVertex2f(500.0,500.0);
				glEnd();
				glDisable(GL_TEXTURE_2D);

	draw(0);
	draw(55);
	draw(110);
	draw(165);
	draw(220);

	setFont(GLUT_BITMAP_TIMES_ROMAN_24);
	glColor3f(1.0,1.0,1.0);
	drawstring(152.0,455.0,1.0,"\t\t\t\t\tRSA ALGORITHM");

	setFont(GLUT_BITMAP_HELVETICA_18);
	glColor3f(1.0,1.0,1.0);
	drawstring(185.0,405.0,1.0,"Press K: Key generation");

	glColor3f(1.0,1.0,1.0);
	drawstring(185.0,350.0,1.0,"Press E: Encryption");

	glColor3f(1.0,1.0,1.0);
	drawstring(185.0,295.0,1.0,"Press T: Message transmission");

	glColor3f(1.0,1.0,1.0);
	drawstring(185.0,240.0,1.0,"Press D :Decryption");

	glColor3f(1.0,1.0,1.0);
	drawstring(185.0,185.0,1.0,"Press X: Exit");

	glColor3f(1.0,1.0,1.0);
	drawstring(400.0,100.0,1.0," Press R -> return");

	glutSwapBuffers();
}

void delay()
{
	int i,j;
	 j=28000;
	while(j!=0)
	{	j--;
		i=28000;
		while(i!=0)
		{	i--;
		}
	}
}
void computer(int a)									// to draw the sender and receiver computers
{
	glColor3f(0.0,0.0,0.0);//monitor
	glBegin(GL_LINE_LOOP);
	glVertex3f(a+25,200,0);
	glVertex3f(a+25,250,0);
	glVertex3f(a+90,250,0);
	glVertex3f(a+90,200,0);
	glEnd();

	glColor3f(0.0,0.0,1.0);//monitor
	glBegin(GL_POLYGON);
	glVertex3f(a+25,200,0);
	glColor3f(0.0,0.6,0.5);
	glVertex3f(a+25,250,0);
	glColor3f(0.0,0.0,1.0);
	glVertex3f(a+90,250,0);
	glVertex3f(a+90,200,0);
	glEnd();
	glFlush();


	glColor3f(1.0,1.0,1.0);// INNER monitor
	glBegin(GL_POLYGON);
	glVertex2f(a+27,202);
	glVertex2f(a+27,248);
	glVertex2f(a+88,248);
	glVertex2f(a+88,202);
	glEnd();
	glFlush();

	glColor3f(0.7,0.0,0.2);//vertical stand
	glBegin(GL_LINES);
	glVertex2f(a+45,200);
	glVertex2f(a+45,195);
	glVertex2f(a+69,200);
	glVertex2f(a+69,195);
	glEnd();
	glFlush();

	glColor3f(0.0,0.392,0.0); //horizontal stand
	glBegin(GL_QUADS);
	glVertex2f(a+38,195);
	glVertex2f(a+77,195);
	glVertex2f(a+77,190);
	glVertex2f(a+38,190);


	glEnd();
	glFlush();



	//glColor3f(5.2,0.6,0.2); //CPU
	glBegin(GL_POLYGON);
	glVertex2f(a+20,190);
	glColor3f(0.0,0.0,1.0);
	glVertex2f(a+95,190);
	glVertex2f(a+95,170);
	glVertex2f(a+20,170);
	glEnd();
	glFlush();

	glBegin(GL_LINE_LOOP);
	glColor3f(1.0,1.0,1.0);
	glVertex2f(a+20,190);
	glVertex2f(a+95,190);
	glVertex2f(a+95,170);
	glVertex2f(a+20,170);
	glEnd();
	glFlush();

	glColor3f(0.7,0.8,0.2);  //CPU CD DRIVE
	glBegin(GL_QUADS);
	glVertex2f(a+35,185);
	glVertex2f(a+55,185);
	glVertex2f(a+55,180);
	glVertex2f(a+35,180);
	glEnd();
	glFlush();



	glColor3f(0.7,0.2,0.8);  //CPU USB
	glBegin(GL_QUADS);
	glVertex2f(a+72,181);
	glVertex2f(a+80,181);
	glVertex2f(a+80,178);
	glVertex2f(a+72,178);
	glEnd();
	glFlush();
}
void keygenval()
{
		srand(time(NULL));
		while(1)
		{
				p = randPrime(SINGLE_MAX);
				q = randPrime(SINGLE_MAX);
				n = p * q;
				if(n < 128) {
					printf("Modulus is less than 128, cannot encode single bytes. Trying again ... ");
				}
				else
					break;
			}
			phi = (p - 1) * (q - 1);
			bytes=1;
			e = randExponent(phi, EXPONENT_MAX);
			d = inverse(e, phi);
}
void keygen()
{

	glClear(GL_COLOR_BUFFER_BIT);
	glBegin(GL_POLYGON);
				glColor3f(0.0,0.1,0.3);
				glVertex2i(0,500);
				glColor3f(0.0,0.5,0.6);
				glVertex2i(0,0);
				glColor3f(0.0,0.5,0.6);
				glVertex2i(500,0);
				glColor3f(0.0,0.1,0.3);
				glVertex2i(500,500);
		glEnd();
		setFont(GLUT_BITMAP_TIMES_ROMAN_24);
		glColor3f(1.0,1.0,1.0);
		drawstring(150.0,480.0,1.0,"KEY GENERATION \n");
		setFont(GLUT_BITMAP_HELVETICA_18);
			glColor3f(0.5,1.0,1.0);

			sprintf(buffer,"%d", p);
			drawstring(12.0,455.0,1.0,"Got first prime factor, p = ");
			glColor3f(0.5,1.0,1.0);
			drawstring(122.0,455.0,1.0,buffer);

			sprintf(buffer,"%d", q);
			glColor3f(0.5,1.0,1.0);
			drawstring(12.0,440.0,1.0,"Got second prime factor, q = ");
			glColor3f(0.5,1.0,1.0);
			drawstring(132.0,440.0,1.0,buffer);

			sprintf(buffer,"%d", n);
			glColor3f(0.5,1.0,1.0);
			drawstring(12.0,425.0,1.0,"Got modulus,n = pq where n = ");
			glColor3f(0.5,1.0,1.0);
			drawstring(144.0,425.0,1.0,buffer);

		sprintf(buffer,"%d", e);
		glColor3f(0.5,1.0,1.0);
		drawstring(12.0,410.0,1.0,"The exponent is = ");
		glColor3f(0.5,1.0,1.0);
		drawstring(90.0,410.0,1.0,buffer);
		glColor3f(0.5,1.0,1.0);
		drawstring(12.0,395.0,1.0,"The public key is =  ");
		glColor3f(0.5,1.0,1.0);
		drawstring(95.0,395.0,1.0,buffer);
		glColor3f(0.5,1.0,1.0);
		drawstring(110.0,395.0,1.0," , ");
		sprintf(buffer,"%d", n);
		glColor3f(0.5,1.0,1.0);
		drawstring(114.0,395.0,1.0,buffer);

		sprintf(buffer,"%d", d);
		glColor3f(0.5,1.0,1.0);
		drawstring(12.0,380.0,1.0,"The private key is =  ");
		glColor3f(0.5,1.0,1.0);
		drawstring(100.0,380.0,1.0,buffer);
		glColor3f(0.5,1.0,1.0);
		drawstring(120.0,380.0,1.0," , ");
		sprintf(buffer,"%d", n);
		glColor3f(0.5,1.0,1.0);
		drawstring(140.0,380.0,1.0,buffer);
		computer(50);
		computer(350);
		glColor3f(0.0,0.0,0.0);
		glBegin(GL_POLYGON);
		glVertex2f(145,190);
		glVertex2f(370,190);
		glVertex2f(370,170);
		glVertex2f(145,170);
		glEnd();

		setFont(GLUT_BITMAP_HELVETICA_12);
		sprintf(buffer,"%d", e);
		drawstring(85.0,215.0,1.0,buffer);
		sprintf(buffer,"%d",n);
		drawstring(100.0,215.0,1.0,buffer);

		if(a>=280.0)
		{
				a=1000.0;
				setFont(GLUT_BITMAP_HELVETICA_12);
				sprintf(buffer,"%d", e);
				drawstring(385.0,215.0,1.0,buffer);
				sprintf(buffer,"%d",n);
				drawstring(400.0,215.0,1.0,buffer);

				setFont(GLUT_BITMAP_HELVETICA_18);
				drawstring(210.0,100.0,1.0,"Key transmitted");
				glFlush();
			}


}

void decryptmes()
{
	int i;
	glClear(GL_COLOR_BUFFER_BIT);

	glBegin(GL_POLYGON);
				glColor3f(0.0,0.1,0.3);
				glVertex2i(0,500);
				glColor3f(0.0,0.5,0.6);
				glVertex2i(0,0);
				glColor3f(0.0,0.5,0.6);
				glVertex2i(500,0);
				glColor3f(0.0,0.1,0.3);
				glVertex2i(500,500);
		glEnd();

		setFont(GLUT_BITMAP_TIMES_ROMAN_24);
		glColor3f(1.0,1.0,1.0);
		drawstring(150.0,480.0,1.0,"DECRYPTION ");
		setFont(GLUT_BITMAP_HELVETICA_18);
		glPushMatrix();
		glTranslatef(0.0,10.0,0.0);
		glScalef(1.8,1.8,1.8);
		computer(0);
		glPopMatrix();

		glEnable(GL_TEXTURE_2D);
		//glColor4f(1.0f, 1.0f, 1.0f, 0.0f);
		tex_2d = SOIL_load_OGL_texture(
				 "rsaf2.png",
				 SOIL_LOAD_RGB,
				 SOIL_CREATE_NEW_ID,
				 SOIL_FLAG_NTSC_SAFE_RGB
			 );
		glBindTexture(GL_TEXTURE_2D, tex_2d);
		glTexEnvf(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
					//determint coordinates of the quad on which you will 'load' an image
		glPushMatrix();
		glRotatef(180,0.0,0.0,0.0);
		glTranslatef(25.0,350.0,0.0);
		glScalef(0.52,0.5,0.5);
		glBegin(GL_POLYGON);
		glColor3f(1.0,1.0,1.0);
		glTexCoord2f(0.0, 0.0);
		glVertex2f(250.0,50.0);
		glTexCoord2f(1.0, 0.0);
		glVertex2f(50.0,50.0);
		glTexCoord2f(1.0, 1.0);
		glVertex2f(50.0,150.0);
		glTexCoord2f(0.0, 1.0);
		glVertex2f(250.0,150.0);
		glEnd();
		glDisable(GL_TEXTURE_2D);
		glPopMatrix();

		drawstring(150.0,200.0,1.0,"The message after decryption is.....");
		decoded = decodeMessage(len/bytes, bytes, encoded, d, n);
		for(i = 0; i < len; i += bytes)
		{
			sprintf(buffer ,"%c ", decoded[i]);
			drawstring(150.0+i*40,160.0,1.0,buffer);
		}
		glColor3f(0.2,0.5,0.6);
		glBegin(GL_LINES);
		glVertex2f(150.0,155.0);
		glVertex2f(150.0+i*50,155.0);
		glEnd();

		glutSwapBuffers();

}
void encryptmes()
{
	int i;
	glClear(GL_COLOR_BUFFER_BIT);

	glBegin(GL_POLYGON);
				glColor3f(0.0,0.1,0.3);
				glVertex2i(0,500);
				glColor3f(0.0,0.5,0.6);
				glVertex2i(0,0);
				glColor3f(0.0,0.5,0.6);
				glVertex2i(500,0);
				glColor3f(0.0,0.1,0.3);
				glVertex2i(500,500);
		glEnd();


		setFont(GLUT_BITMAP_TIMES_ROMAN_24);
		glColor3f(1.0,1.0,1.0);
		drawstring(150.0,480.0,1.0,"ENCRYPTION ");
		setFont(GLUT_BITMAP_HELVETICA_18);
		glPushMatrix();
		glTranslatef(0.0,10.0,0.0);
		glScalef(1.8,1.8,1.8);
		computer(0);
		glPopMatrix();

		glEnable(GL_TEXTURE_2D);
		//glColor4f(1.0f, 1.0f, 1.0f, 0.0f);
		tex_2d = SOIL_load_OGL_texture(
				 "rsaf1.jpg",
				 SOIL_LOAD_RGB,
				 SOIL_CREATE_NEW_ID,
				 SOIL_FLAG_NTSC_SAFE_RGB
			 );

		glBindTexture(GL_TEXTURE_2D, tex_2d);
		glTexEnvf(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
		glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
					//determint coordinates of the quad on which you will 'load' an image
		glPushMatrix();
		glRotatef(180,0.0,0.0,0.0);
		glTranslatef(25.0,350.0,0.0);
		glScalef(0.52,0.5,0.5);
		glBegin(GL_POLYGON);
		glColor3f(1.0,1.0,1.0);
		glTexCoord2f(0.0, 0.0);
		glVertex2f(250.0,50.0);
		glTexCoord2f(1.0, 0.0);
		glVertex2f(50.0,50.0);
		glTexCoord2f(1.0, 1.0);
		glVertex2f(50.0,150.0);
		glTexCoord2f(0.0, 1.0);
		glVertex2f(250.0,150.0);
		glEnd();
		glDisable(GL_TEXTURE_2D);
		glPopMatrix();

		drawstring(150.0,200.0,1.0,"The message after encryption is.....");
		encoded = encodeMessage(len, bytes, string, e, n);
		for(i = 0; i < len; i += bytes)
		{
			sprintf(buffer ,"%d ", encoded[i/bytes]);
			drawstring(150.0+i*40,160.0,1.0,buffer);
		}
		glColor3f(0.2,0.5,0.6);
		glBegin(GL_LINES);
		glVertex2f(150.0,155.0);
		glVertex2f(150.0+i*50,155.0);
		glEnd();
		glColor3f(0.0,0.0,0.0);
		for(i = 0; i < len; i += bytes)
		{
			sprintf(buffer ,"%c ", string[i]);
			drawstring(150.0+i*50,140.0,1.0,buffer);
		}

		glutSwapBuffers();

}

void message(int a)
{
	glColor3f(0.0,0.0,1.0);
	glBegin(GL_POLYGON);
	glVertex3f(a+20,750,0);
	glVertex3f(a+20,800,0);
	glVertex3f(a+90,800,0);
	glVertex3f(a+90,750,0);
	glEnd();
	glFlush();

	glColor3f(0.0,0.5,0.5);
	glBegin(GL_POLYGON);
	glVertex3f(a+90,800,0);
	glVertex3f(a+20,800,0);
	glVertex3f(a+55,775,0);
	glEnd();
	glFlush();

}

void mykeyboard(unsigned char key,int x,int y)
{
	switch(key)
	{
		case 'x':
		case 'X':exit(0);break;
		case 's':
		case 'S':
	  case 'a':
		case 'A':
		case 'b':
		case 'B':
		case 'c':
		case 'C':break;
		case 'd':
		case 'D':flag=1;flag1=4;glutPostRedisplay();break;
		case 'f':
		case 'F':
		case 'g':
		case 'G':
		case 'h':
		case 'H':
		case 'i':
		case 'I':
		case 'j':
		case 'J':break;
		case 'k':
		case 'K':keygenval();flag1=1;a=126.0;glutPostRedisplay();break;
		case 'e':
		case 'E':flag=1;flag1=2;glutPostRedisplay();break;
		case 'r':
		case 'R':flag=0;glutPostRedisplay();break;
		case 'p':
		case 'P':
		case 't':
		case 'T':flag=1,flag1=3;glutPostRedisplay();break;
		case 'y':
		case 'Y':flag=1;flag1=0;glutPostRedisplay();break;
		case 'n':
		case 'N':exit(0);break;
		case 'm':
		case 'M':flag=1;flag1=0;glutPostRedisplay();break;
		default:return;
	}
	glutPostRedisplay();
}


void myInit()
{
    	glClearColor(0.0,0.0,0.0,0.0);
			glColor3f(0.0f,0.0f,0.0f);
			glBegin(GL_POLYGON);
						glColor3f(0.0,0.1,0.3);
						glVertex2i(0,500);
						glColor3f(0.0,0.5,0.6);
						glVertex2i(0,0);
						glColor3f(0.0,0.5,0.6);
						glVertex2i(500,0);
						glColor3f(0.0,0.1,0.3);
						glVertex2i(500,500);
				glEnd();
			glPointSize(5.0);

			glMatrixMode(GL_PROJECTION);
			glLoadIdentity();
			gluOrtho2D(0.0,500.0,0.0,500.0);
			glMatrixMode(GL_MODELVIEW);
			glLoadIdentity();
}

void messaget()
{
	glBegin(GL_POLYGON);
				glColor3f(0.0,0.1,0.3);
				glVertex2i(0,500);
				glColor3f(0.0,0.5,0.6);
				glVertex2i(0,0);
				glColor3f(0.0,0.5,0.6);
				glVertex2i(500,0);
				glColor3f(0.0,0.1,0.3);
				glVertex2i(500,500);
		glEnd();
		setFont(GLUT_BITMAP_HELVETICA_18);
		glColor3f(0.0,0.0,0.0);
		drawstring(150.0,480.0,1.0,"MESSAGE TRANSMISSION");
		glPushMatrix();
		glScalef(1.5,1.5,1.5);
		computer(0);
		glPopMatrix();
		glPushMatrix();
		glTranslatef(0.0,-50.0,0.0);
		glScalef(1.5,1.5,1.5);
		computer(200);
		glPopMatrix();
		glColor3f(0.0,0.0,0.0);
		drawstring(50.0,320.0,1.0,"Message Sent");
		if(b>=850)
		 drawstring(350.0,300.0,1.0,"Message recieved");
}

void display(void)
{
	glClear(GL_COLOR_BUFFER_BIT);
	if(flag==0)
	{
		title();
	}
	if(flag==1)
	{
		if(flag1==0)
 		text();
		else if(flag1==1)
		{
			keygen();
			while(1)
			{
			glClear(GL_COLOR_BUFFER_BIT);
			keygen();
			glPushMatrix();
			glTranslatef(a,0.0,0.0);
			glScalef(0.2,0.2,0.2);
			glPushMatrix();
			glTranslated(a,0.0,0.0);
			glColor3f(0.85,0.85,0.10);
			glBegin(GL_POLYGON);//rectangular body
			glVertex2f(122.0,910.0);
			glVertex2f(212.0,910.0);
			glVertex2f(212.0,890.0);
			glVertex2f(122.0,890.0);
			glEnd();
			glPopMatrix();

			glPushMatrix();
			glTranslated(a,0.0,0.0);
			glColor3f(0.85,0.85,0.10);
			glBegin(GL_POLYGON);
			glVertex2f(202.0,890.0);
			glVertex2f(202.0,875.0);
			glVertex2f(194.0,875.0);
			glVertex2f(194.0,890.0);
			glEnd();
			glPopMatrix();

			glPushMatrix();
			glTranslated(a,0.0,0.0);
			glColor3f(0.85,0.85,0.10);
			glBegin(GL_POLYGON);
			glVertex2f(184.0,890.0);
			glVertex2f(184.0,883.0);
			glVertex2f(186.0,883.0);
			glVertex2f(186.0,890.0);
			glEnd();
			glPopMatrix();

			glPushMatrix();
			glTranslated(a,0.0,0.0);
			glColor3f(0.85,0.85,0.10);
			glBegin(GL_TRIANGLE_FAN);
			glVertex2f(100.0,900.0);
				for(ang=1.0f;ang<361;ang+=0.2)
				{
					x2=100.0+sin(ang)*23;
					y2=900.0+cos(ang)*23;
					glVertex2f(x2,y2);
			}
			glEnd();
			glPopMatrix();

			glPushMatrix();
			glTranslated(a,0.0,0.0);
			glColor3f(0.0,0.0,0.0);
			glBegin(GL_TRIANGLE_FAN);
			glVertex2f(100.0,900.0);
				for(ang=1.0f;ang<361;ang+=0.2)
				{
					x2=100.0+sin(ang)*15;
					y2=900.0+cos(ang)*15;
					glVertex2f(x2,y2);
			}
			glEnd();
			glPopMatrix();
			//delay();
			/*glPushMatrix();
			glColor3f(0.0,0.0,00.0);
			glBegin(GL_POLYGON);//rectangular body
			glVertex2f(100.0,910.0);
			glVertex2f(212.0,910.0);
			glVertex2f(212.0,850.0);
			glVertex2f(100.0,850.0);
			glEnd();*/
				glutPostRedisplay();

			glPopMatrix();
			glutSwapBuffers();


			a=a+0.5;
			if(a>280.0)
			{
				a+=120;
				break;
			}
		}
	}
	else if(flag1==2)
	{
		encryptmes();
	}
	else if(flag1==3)
	{
		messaget();
		while(1)
		{
			glClear(GL_COLOR_BUFFER_BIT);
			messaget();
			glPushMatrix();
			glScalef(0.3,0.3,0.3);
			glTranslatef(b,c,0.0);
			message(200);
			glPopMatrix();

			glutPostRedisplay();
			glutSwapBuffers();
			if(c>120)
			  c=c-20.0;
			if(c<120 && b<850)
				b=b+3.0;
			if(b>=850)
			{
				b=b+200.0;
				break;
			}
		}
	}
	else if(flag1==4)
	{
		decryptmes();
	}
	}

}

int main(int argc, char ** argv)
{
     	printf("\nEnter a message less than ten characters\n");
     	scanf("%s",string);
			len=strlen(string);
			glutInit(&argc,argv);
      glutInitDisplayMode(GLUT_RGBA|GLUT_DOUBLE);
      glutInitWindowPosition(0,0);
      glutInitWindowSize(1000,1000);
      glutCreateWindow("RSA ");
      glutKeyboardFunc(mykeyboard);
      glutDisplayFunc(display);
      myInit();
      glutMainLoop();
}
