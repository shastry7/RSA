#include<GL/glut.h>
#include<stdio.h>
#include<stdlib.h>
#include<time.h>
#include<string.h>


#define		mainmenu		100
#define  keygeny         0
#define   transmitkey   1
#define  encrypt		2
#define  decrypt    3
#define  exite		4

#define ACCURACY 5
#define SINGLE_MAX 10000
#define EXPONENT_MAX 1000



int flag=0;
int p, q, n, phi, e, d, bytes, len;
int *encoded, *decoded;
char string[20];
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
		printf("%d ", encoded[i/bytes]);
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

void title()												// to draw the starting screen
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
			glColor3f(1.0,1.0,1.0);
			drawstring(20.0,435.0,1.0,"     RIVEST SHAMIR ADLEMAN ALGORITHM VISUALIZATION      ");
			glColor3f(1.0,1.0,1.0);
			drawstring(210.0,365.0,1.0,"		SUBMITTED BY	");
			glColor3f(1.0,1.0,1.0);
			drawstring(180.0,340.0,1.0,"APOORVA SHASTRY 1PE13CS030");
			glColor3f(1.0,1.0,1.0);
			drawstring(180.0,320.0,1.0,"DARA SRAVYA\t\t\t\t\t\t\t\t\t\t\t\t1PE13CS050");
			glColor3f(1.0,1.0,1.0);
			drawstring(400.0,100.0,1.0," Press M -> continue");
			glFlush();
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
	draw(0);
	draw(55);
	draw(110);
	draw(165);
	draw(220);

	setFont(GLUT_BITMAP_HELVETICA_18);
	glColor3f(0.5,1.0,1.0);
	drawstring(152.0,455.0,1.0,"\t\t\t\t\t\tRSA ALGORITHM");

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
	glFlush();
}




void computer(int a)									// to draw the sender and receiver computers
{

	glColor3f(0.0,0.0,1.0);//monitor
	glBegin(GL_LINE_LOOP);
	glVertex3f(a+25,200,0);
	glVertex3f(a+25,250,0);
	glVertex3f(a+90,250,0);
	glVertex3f(a+90,200,0);
	glEnd();
	glFlush();


	glColor3f(0.0,1.0,0.0);// INNER monitor
	glBegin(GL_LINE_LOOP);
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
void cir(float xc,float yc,float r)
{
    float x1,y1,x2,y2;
    float ang;
    double radius=r;

    x1=xc,y1=yc;
    glColor3f(0.85,0.85,0.10);

    glBegin(GL_TRIANGLE_FAN);
    glVertex2f(x1,y1);

    for(ang=1.0f;ang<361;ang+=0.2)
    {
        x2=x1+sin(ang)*radius;
        y2=y1+cos(ang)*radius;
        glVertex2f(x2,y2);
    }
    glEnd();
}

void Rec_draw(GLfloat x1,GLfloat y1)
{
    glColor3f(0.85,0.85,0.10);
    //glPolygonMode(GL_FRONT_AND_BACK,GL_FILL);
    glBegin(GL_POLYGON);
    glVertex2f(x1,y1);
    glVertex2f(x1+150,y1);
    glVertex2f(x1+150,y1-20);
    glVertex2f(x1,y1-20);
    glEnd();
    glBegin(GL_POLYGON);
    glVertex2f(x1+140,y1-20);
    glVertex2f(x1+140,y1-55);
    glVertex2f(x1+132,y1-55);
    glVertex2f(x1+132,y1-20);
    glEnd();
    glBegin(GL_POLYGON);
    glVertex2f(x1+122,y1-20);
    glVertex2f(x1+122,y1-37);
    glVertex2f(x1+114,y1-37);
    glVertex2f(x1+114,y1-20);

    glEnd();
}

void key(float xc,float yc,float r)
{
;
    glClear(GL_COLOR_BUFFER_BIT);
    glColor3f(1.0,0.0,0.0);
    glPointSize(2.0);
    cir(sc,yc,r);
    Rec_draw(xc+r-1,yc+10);
    glFlush();
}


void keygen()
{
	char buffer[256];
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
		setFont(GLUT_BITMAP_HELVETICA_18);
		glColor3f(0.5,1.0,1.0);
		drawstring(150.0,480.0,1.0,"KEY GENERATION ");
		srand(time(NULL));
		setFont(GLUT_BITMAP_HELVETICA_18);
		while(1)
		{
			glColor3f(0.5,1.0,1.0);
			p = randPrime(SINGLE_MAX);
			sprintf(buffer,"%d", p);
			drawstring(12.0,455.0,1.0,"Got first prime factor, p = ");
			glColor3f(0.5,1.0,1.0);
			drawstring(122.0,455.0,1.0,buffer);
			q = randPrime(SINGLE_MAX);
			sprintf(buffer,"%d", q);
			glColor3f(0.5,1.0,1.0);
			drawstring(12.0,440.0,1.0,"Got second prime factor, q = ");
			glColor3f(0.5,1.0,1.0);
			drawstring(132.0,440.0,1.0,buffer);
			n = p * q;
			sprintf(buffer,"%d", n);
			glColor3f(0.5,1.0,1.0);
			drawstring(12.0,425.0,1.0,"Got modulus,n = pq where n = ");
			glColor3f(0.5,1.0,1.0);
			drawstring(144.0,425.0,1.0,buffer);
			if(n < 128) {
				printf("Modulus is less than 128, cannot encode single bytes. Trying again ... ");
			}
			else
				break;
		}
		phi = (p - 1) * (q - 1);
		bytes=1;
		e = randExponent(phi, EXPONENT_MAX);
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
		d = inverse(e, phi);
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
		glFlush();
}


void mykeyboard(unsigned char key,int x,int y)
{
	switch(key)
	{
		case 'x':
		case 'X':exit(0);break;
		case 'e':
		case 'E':
		case 's':
		case 'S':
	  	case 'a':
		case 'A':
		case 'b':
		case 'B':
		case 'c':
		case 'C':
		case 'd':
		case 'D':
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
		case 'K':keygen();break;
		case 'w':
		case 'W':
		case 'r':
		case 'R':
		case 'p':
		case 'P':
		case 't':
		case 'T':break;
		case 'y':
		case 'Y':flag=1;glutPostRedisplay();break;
		case 'n':
		case 'N':exit(0);break;
		case 'm':
		case 'M':flag=1;glutPostRedisplay();break;
		default:return;
	}
	//glutPostRedisplay();
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
			gluOrtho2D(0.0,500.0,0.0,500.0);
			glMatrixMode(GL_PROJECTION);
			glLoadIdentity();
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
		text();
	}

}

int main(int argc, char ** argv)
{
     	printf("\nEnter a message less than ten characters\n");
     	scanf("%s",string);
			glutInit(&argc,argv);
      glutInitDisplayMode(GLUT_SINGLE|GLUT_RGBA);
      glutInitWindowPosition(0,0);
      glutInitWindowSize(1000,1000);
      glutCreateWindow("RSA ");
      glutKeyboardFunc(mykeyboard);
      glutDisplayFunc(display);
      myInit();
      glutMainLoop();
}
