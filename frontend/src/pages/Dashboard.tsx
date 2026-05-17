import { motion } from 'framer-motion';
import { AlertTriangle, Bot, CheckCircle2, Clock, FileText, ShieldCheck, Users } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Badge } from '../components/ui/badge';
import { Card, CardTitle } from '../components/ui/card';

const stats = [
  { label: 'Aktiv topshiriqlar', value: 128, icon: FileText, tone: 'text-blue-600' },
  { label: 'Kechikkan', value: 14, icon: AlertTriangle, tone: 'text-red-600' },
  { label: 'Bugun tugaydi', value: 27, icon: Clock, tone: 'text-amber-600' },
  { label: 'Bajarildi', value: 439, icon: CheckCircle2, tone: 'text-emerald-600' }
];

const chart = [
  { name: 'Dush', tasks: 42, overdue: 4 },
  { name: 'Sesh', tasks: 51, overdue: 7 },
  { name: 'Chor', tasks: 38, overdue: 2 },
  { name: 'Pay', tasks: 64, overdue: 8 },
  { name: 'Jum', tasks: 49, overdue: 3 }
];

export function Dashboard() {
  return (
    <main className="min-h-screen bg-slate-50 text-slate-950 dark:bg-slate-950 dark:text-white">
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-border bg-white p-5 dark:bg-slate-900 lg:block">
        <div className="mb-8 flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-xl bg-blue-700 text-white"><ShieldCheck size={20} /></div>
          <div>
            <b>Ijro AI</b>
            <p className="m-0 text-xs text-slate-500">Enterprise monitoring</p>
          </div>
        </div>
        {['Dashboard', 'Hujjatlar', 'Topshiriqlar', 'Xodimlar', 'Telegram bot', 'AI tavsiyalar', 'Audit log'].map((item, index) => (
          <button key={item} className={`mb-2 w-full rounded-lg px-3 py-2 text-left text-sm font-semibold ${index === 0 ? 'bg-blue-700 text-white' : 'text-slate-600 hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800'}`}>
            {item}
          </button>
        ))}
      </aside>

      <section className="lg:pl-72">
        <header className="sticky top-0 z-10 border-b border-border bg-white/90 px-6 py-4 backdrop-blur dark:bg-slate-950/85">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="m-0 text-xl font-bold">Rahbar monitoring paneli</h1>
              <p className="m-0 text-sm text-slate-500">Realtime edu.ijro nazorati, AI risk va Telegram ijro holati</p>
            </div>
            <Badge className="bg-emerald-50 text-emerald-700">Realtime active</Badge>
          </div>
        </header>

        <div className="grid gap-5 p-6">
          <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            {stats.map((stat, index) => (
              <motion.div key={stat.label} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: index * 0.06 }}>
                <Card>
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="m-0 text-xs font-semibold uppercase text-slate-500">{stat.label}</p>
                      <b className="mt-2 block text-3xl">{stat.value}</b>
                    </div>
                    <stat.icon className={stat.tone} />
                  </div>
                </Card>
              </motion.div>
            ))}
          </div>

          <div className="grid gap-5 xl:grid-cols-[1.4fr_.9fr]">
            <Card>
              <CardTitle>Haftalik yuklama va kechikishlar</CardTitle>
              <div className="mt-4 h-80">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chart}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Bar dataKey="tasks" fill="#1d4ed8" radius={[6, 6, 0, 0]} />
                    <Bar dataKey="overdue" fill="#dc2626" radius={[6, 6, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Card>
            <Card>
              <CardTitle>AI tavsiyalar</CardTitle>
              <div className="mt-4 space-y-3">
                {[
                  ['CRITICAL', '25-06/5088-sonli topshiriq bo‘yicha muddat riski yuqori.'],
                  ['URGENT', 'Qurilish nazorati bo‘limida yuklama 82% ga yetdi.'],
                  ['IMPORTANT', '3 ta duplicate topshiriq birlashtirish uchun tavsiya qilindi.']
                ].map(([level, text]) => (
                  <div key={text} className="rounded-lg border border-border bg-slate-50 p-3 dark:bg-slate-800">
                    <Badge className="mb-2 bg-blue-50 text-blue-700">{level}</Badge>
                    <p className="m-0 text-sm text-slate-700 dark:text-slate-200">{text}</p>
                  </div>
                ))}
              </div>
            </Card>
          </div>

          <Card>
            <CardTitle>Telegram ijro holati</CardTitle>
            <div className="mt-4 grid gap-3 md:grid-cols-3">
              <div className="rounded-lg bg-slate-50 p-4 dark:bg-slate-800"><Bot className="mb-2 text-blue-600" /> 92 xodim botga ulangan</div>
              <div className="rounded-lg bg-slate-50 p-4 dark:bg-slate-800"><Users className="mb-2 text-emerald-600" /> 37 ta bugungi tasdiq</div>
              <div className="rounded-lg bg-slate-50 p-4 dark:bg-slate-800"><Clock className="mb-2 text-amber-600" /> 18 ta reminder navbatda</div>
            </div>
          </Card>
        </div>
      </section>
    </main>
  );
}
