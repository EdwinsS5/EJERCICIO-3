int num1;
int num2;

Console.WriteLine("Primer numero:");
num1 = Convert.ToInt32(Console.ReadLine());

Console.WriteLine("Primer numero:");
num2 = Convert.ToInt32(Console.ReadLine());
void saludar()
{
    Console.WriteLine("Que onda");
}
int opcion;
Console.WriteLine("Que deseas hacer");
Console.WriteLine("1. suma:");
Console.WriteLine("2. resta:");
Console.WriteLine("3. multiplicacion:");
Console.WriteLine("4. divicion:");
opcion = Convert.ToInt32(Console.ReadLine());

switch (opcion)
{
    case 1:
        {
            Console.WriteLine()
            break;
        }
}

int suma()
{

    return num1 + num2;

}

int Mult(int n1, int n2)
{
    int resultad = n1 * n2;
    return resultad;

}
int div(int n1, int n2)
{
    int resultad = n1 / n2;
    return resultad;

}
int resta(int n1, int n2)
{
    int resultad = n1 - n2;
    return resultad;

}
saludar();



Console.WriteLine($"la suma es: {respuesta}");
respuesta = resta(num1, num2);
Console.WriteLine($"la resta es: {respuesta}");
respuesta = Mult(num1, num2);
Console.WriteLine($"la multiplicacion es: {respuesta}");
respuesta = div(num1, num2);
Console.WriteLine($"la divicion es: {respuesta}");
