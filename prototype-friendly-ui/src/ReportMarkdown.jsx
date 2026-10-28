import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export default function ReportMarkdown({ children }) {
  return <ReactMarkdown remarkPlugins={[remarkGfm]}>{children}</ReactMarkdown>;
}
