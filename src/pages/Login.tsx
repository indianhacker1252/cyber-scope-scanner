import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, AlertCircle } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';
import { Alert, AlertDescription } from '@/components/ui/alert';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [lockoutMessage, setLockoutMessage] = useState('');
  const [attemptsRemaining, setAttemptsRemaining] = useState<number | null>(null);
  const navigate = useNavigate();
  const { toast } = useToast();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setLockoutMessage('');
    setAttemptsRemaining(null);

    try {
      const { data, error } = await supabase.functions.invoke('auth-login', {
        body: { username, password }
      });

      if (error || data?.error) {
        if (data?.locked) {
          setLockoutMessage(data.error);
        } else {
          toast({
            title: 'Login Failed',
            description: data?.error || 'Invalid credentials',
            variant: 'destructive',
          });
          if (data?.attemptsRemaining !== undefined) {
            setAttemptsRemaining(data.attemptsRemaining);
          }
        }
        setLoading(false);
        return;
      }

      // Set session
      if (data.session) {
        await supabase.auth.setSession({
          access_token: data.session.access_token,
          refresh_token: data.session.refresh_token,
        });

        // Store user role
        localStorage.setItem('userRole', data.role);

        toast({
          title: 'Login Successful',
          description: `Welcome back, ${username}!`,
        });

        navigate('/');
      }
    } catch (err) {
      console.error('Login error:', err);
      toast({
        title: 'Error',
        description: 'An unexpected error occurred',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-background via-background/95 to-primary/10 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-3 text-center">
          <div className="mx-auto w-16 h-16 bg-primary/10 rounded-full flex items-center justify-center">
            <Shield className="w-8 h-8 text-primary" />
          </div>
          <CardTitle className="text-2xl">VAPT Tool Login</CardTitle>
          <CardDescription>
            Enter your credentials to access the Vulnerability Assessment & Penetration Testing Tool
          </CardDescription>
          {username === '' && password === '' && (
            <Alert className="text-left">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription className="text-sm">
                Default credentials: <strong>kali</strong> / <strong>kali</strong>
              </AlertDescription>
            </Alert>
          )}
        </CardHeader>
        <CardContent>
          {lockoutMessage && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{lockoutMessage}</AlertDescription>
            </Alert>
          )}

          {!lockoutMessage && attemptsRemaining !== null && attemptsRemaining < 3 && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                Warning: {attemptsRemaining} attempt{attemptsRemaining !== 1 ? 's' : ''} remaining before lockout
              </AlertDescription>
            </Alert>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                type="text"
                placeholder="Enter your username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                disabled={loading || !!lockoutMessage}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={loading || !!lockoutMessage}
              />
            </div>
            <Button 
              type="submit" 
              className="w-full" 
              disabled={loading || !!lockoutMessage}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>
          </form>

          <div className="mt-6 text-center text-sm text-muted-foreground">
            <p>© 2024 Harsh Malik - All Rights Reserved</p>
            <p className="mt-1">Authorized Access Only</p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}