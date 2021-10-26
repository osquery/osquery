#include <iostream>
using namespace std;
int main()
{
    int choice,a,b,c,d;
    cout<<"\t\tMINI CALCULATOR";
    for(;;)
    {
        cout<<"\n\nSelect an operation:";
        cout<<"\n1 add\n2 sub\n3 multiply\n4 divide\n5 QUIT";
        cout<<"\nenter your choice:";
        cin>>choice;
        if(choice>5)
         {
            cout<<"WRONG CHOICE . TRY AGAIN!!";
            continue;
         }
        switch(choice)
        {
        case 1:
             cout<<"enter 2 no.:";
             cin>>a>>b;
             cout<<"sum is" << a+b;
             continue;

        case 2:
             cout<<"enter 2 no.:";
             cin>>a>>b;
             cout<<"subtraction" <<a-b;
             continue;
        case 3:
             cout<<"enter 2 no.:";
             cin>>a>>b;
             cout<<"multiplication is" <<a*b;
             continue;
        case 4:
             cout<<"enter 2 no.:";
             cin>>c>>d;
             cout<<"division is" <<c/d;
             continue;
        case 5:
            cout<<"\n\tTHANK YOU FOR USING MINI CALCULATOR.\n\t\tHAVE A NICE DAY!!";
            if(choice==5)
                break;
        }
        return 0;
    }

}
